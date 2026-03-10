package runner

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/subfinder/v2/pkg/subscraping"
)

// ReportSubdomain holds data for a single subdomain entry in the report
type ReportSubdomain struct {
	Host                string
	Sources             []string
	WildcardCertificate bool
}

// ReportDomainData holds all collected data for one target domain
type ReportDomainData struct {
	Domain     string
	Subdomains []ReportSubdomain
	Duration   time.Duration
	Statistics map[string]subscraping.Statistics
}

// ReportData holds all data needed to render the HTML report
type ReportData struct {
	Domains   []ReportDomainData
	StartTime time.Time
	EndTime   time.Time
}

// NewReportData creates a new empty ReportData
func NewReportData() *ReportData {
	return &ReportData{StartTime: time.Now()}
}

// AddDomainData appends results for a domain to the report
func (rd *ReportData) AddDomainData(domain string, sourceMap map[string]map[string]struct{}, duration time.Duration, stats map[string]subscraping.Statistics) {
	var subs []ReportSubdomain
	for host, sources := range sourceMap {
		var srcList []string
		for src := range sources {
			srcList = append(srcList, src)
		}
		sort.Strings(srcList)
		subs = append(subs, ReportSubdomain{Host: host, Sources: srcList})
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i].Host < subs[j].Host })

	rd.Domains = append(rd.Domains, ReportDomainData{
		Domain:     domain,
		Subdomains: subs,
		Duration:   duration,
		Statistics: stats,
	})
}

type reportInsightHost struct {
	Domain      string
	Host        string
	Depth       int
	RiskScore   int
	Tags        []string
	SourceCount int
}

type sourceHealth struct {
	Source        string
	Results       int
	Requests      int
	Errors        int
	AvgDurationMs int64
}

type sourceCount struct {
	Name  string
	Count int
}

func hostRisk(host string) (int, []string) {
	labels := []struct {
		key   string
		tag   string
		score int
	}{
		{key: "admin", tag: "admin", score: 18},
		{key: "internal", tag: "internal", score: 15},
		{key: "vpn", tag: "vpn", score: 16},
		{key: "gateway", tag: "gateway", score: 12},
		{key: "bastion", tag: "bastion", score: 16},
		{key: "grafana", tag: "observability", score: 12},
		{key: "kibana", tag: "observability", score: 12},
		{key: "jenkins", tag: "ci/cd", score: 17},
		{key: "argocd", tag: "ci/cd", score: 16},
		{key: "gitlab", tag: "ci/cd", score: 14},
		{key: "api", tag: "api", score: 8},
		{key: "auth", tag: "auth", score: 12},
		{key: "oauth", tag: "auth", score: 12},
		{key: "sso", tag: "auth", score: 12},
		{key: "db", tag: "database", score: 14},
		{key: "redis", tag: "database", score: 14},
		{key: "mongo", tag: "database", score: 14},
		{key: "kafka", tag: "messaging", score: 10},
		{key: "rabbit", tag: "messaging", score: 10},
		{key: "dev", tag: "env-dev", score: 10},
		{key: "stage", tag: "env-stage", score: 10},
		{key: "staging", tag: "env-stage", score: 10},
		{key: "qa", tag: "env-qa", score: 8},
		{key: "uat", tag: "env-uat", score: 8},
		{key: "test", tag: "env-test", score: 8},
		{key: "sandbox", tag: "env-sandbox", score: 8},
		{key: "legacy", tag: "legacy", score: 9},
		{key: "old", tag: "legacy", score: 7},
		{key: "backup", tag: "backup", score: 12},
		{key: "debug", tag: "debug", score: 12},
	}

	lower := strings.ToLower(host)
	risk := 5
	tagSet := make(map[string]struct{})
	for _, marker := range labels {
		if strings.Contains(lower, marker.key) {
			risk += marker.score
			tagSet[marker.tag] = struct{}{}
		}
	}
	if strings.Count(host, ".") >= 4 {
		risk += 5
		tagSet["deep-nesting"] = struct{}{}
	}
	if risk > 100 {
		risk = 100
	}
	if len(tagSet) == 0 {
		tagSet["general"] = struct{}{}
	}

	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return risk, tags
}

func toQuotedJSArray(values []string) string {
	quoted := make([]string, 0, len(values))
	for _, value := range values {
		quoted = append(quoted, fmt.Sprintf(`"%s"`, html.EscapeString(value)))
	}
	return strings.Join(quoted, ",")
}

func topKeywordHTML(keywordMap map[string]int, limit int) string {
	type kv struct {
		Key   string
		Value int
	}
	pairs := make([]kv, 0, len(keywordMap))
	for key, value := range keywordMap {
		pairs = append(pairs, kv{Key: key, Value: value})
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].Value > pairs[j].Value })
	if len(pairs) > limit {
		pairs = pairs[:limit]
	}

	var sb strings.Builder
	for _, pair := range pairs {
		sb.WriteString(fmt.Sprintf(`<button type="button" class="pill keyword-pill" data-keyword="%s" onclick="applyKeywordFilter(this.dataset.keyword)"><span>%s</span><strong>%d</strong></button>`, html.EscapeString(pair.Key), html.EscapeString(pair.Key), pair.Value))
	}
	if sb.Len() == 0 {
		return `<div class="muted">No keyword signals detected.</div>`
	}
	return sb.String()
}

func topSourcesHTML(sourceCounts []sourceCount, limit int) string {
	var sb strings.Builder
	if len(sourceCounts) > limit {
		sourceCounts = sourceCounts[:limit]
	}
	for _, source := range sourceCounts {
		sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td></tr>`, html.EscapeString(source.Name), source.Count))
	}
	if sb.Len() == 0 {
		return `<tr><td colspan="2">No data</td></tr>`
	}
	return sb.String()
}

func sourceHealthHTML(health []sourceHealth, limit int) string {
	sort.Slice(health, func(i, j int) bool {
		left := float64(health[i].Errors) / float64(max(1, health[i].Requests))
		right := float64(health[j].Errors) / float64(max(1, health[j].Requests))
		if left == right {
			return health[i].Requests > health[j].Requests
		}
		return left > right
	})

	if len(health) > limit {
		health = health[:limit]
	}

	var sb strings.Builder
	for _, entry := range health {
		errorRate := int(float64(entry.Errors) / float64(max(1, entry.Requests)) * 100)
		className := "ok"
		if errorRate >= 30 {
			className = "bad"
		} else if errorRate >= 10 {
			className = "warn"
		}
		sb.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%d</td><td>%d</td><td class="%s">%d%%</td><td>%dms</td></tr>`,
			html.EscapeString(entry.Source), entry.Results, entry.Requests, className, errorRate, entry.AvgDurationMs,
		))
	}
	if sb.Len() == 0 {
		return `<tr><td colspan="5">No stats available (run with --stats)</td></tr>`
	}
	return sb.String()
}

func tagsHTML(tags []string) string {
	var sb strings.Builder
	for _, tag := range tags {
		sb.WriteString(fmt.Sprintf(`<span class="tag">%s</span>`, html.EscapeString(tag)))
	}
	return sb.String()
}

func riskClass(score int) string {
	if score >= 65 {
		return "critical"
	}
	if score >= 45 {
		return "high"
	}
	if score >= 25 {
		return "medium"
	}
	return "low"
}

func riskTableHTML(items []reportInsightHost, limit int) string {
	sort.Slice(items, func(i, j int) bool {
		if items[i].RiskScore == items[j].RiskScore {
			return items[i].Host < items[j].Host
		}
		return items[i].RiskScore > items[j].RiskScore
	})
	if len(items) > limit {
		items = items[:limit]
	}

	var sb strings.Builder
	for _, item := range items {
		riskKeywords := strings.ToLower(strings.Join(item.Tags, " ") + " " + item.Host)
		sb.WriteString(fmt.Sprintf(`<tr data-host="%s" data-keywords="%s"><td>%s</td><td class="mono">%s</td><td>%d</td><td><span class="risk %s">%d</span></td><td>%s</td></tr>`,
			html.EscapeString(strings.ToLower(item.Host)),
			html.EscapeString(riskKeywords),
			html.EscapeString(item.Domain),
			html.EscapeString(item.Host),
			item.SourceCount,
			riskClass(item.RiskScore),
			item.RiskScore,
			tagsHTML(item.Tags),
		))
	}
	if sb.Len() == 0 {
		return `<tr><td colspan="5">No hosts available</td></tr>`
	}
	return sb.String()
}

// GenerateHTMLReport writes a self-contained HTML report to the given file path
func (rd *ReportData) GenerateHTMLReport(outputPath string) error {
	rd.EndTime = time.Now()

	dir := filepath.Dir(outputPath)
	if dir != "" {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			if mkErr := os.MkdirAll(dir, os.ModePerm); mkErr != nil {
				return mkErr
			}
		}
	}

	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("could not create report file: %w", err)
	}
	defer f.Close()

	totalDuration := rd.EndTime.Sub(rd.StartTime)

	var targetDomains []string
	totalSubdomains := 0
	totalSourceLinks := 0
	maxDepth := 1
	totalRisk := 0
	totalHosts := 0

	sourceCountMap := make(map[string]int)
	keywordMap := map[string]int{
		"admin": 0,
		"api": 0,
		"auth": 0,
		"internal": 0,
		"vpn": 0,
		"dev": 0,
		"staging": 0,
		"stage": 0,
		"prod": 0,
		"preprod": 0,
		"qa": 0,
		"uat": 0,
		"test": 0,
		"sandbox": 0,
		"legacy": 0,
		"gateway": 0,
		"sso": 0,
		"oauth": 0,
		"db": 0,
		"sql": 0,
		"redis": 0,
		"mongo": 0,
		"kafka": 0,
		"rabbit": 0,
		"jenkins": 0,
		"argocd": 0,
		"grafana": 0,
		"kibana": 0,
		"mail": 0,
		"ftp": 0,
		"portal": 0,
		"cms": 0,
		"billing": 0,
		"payments": 0,
		"hr": 0,
		"finance": 0,
	}
	statAgg := make(map[string]sourceHealth)
	insightHosts := make([]reportInsightHost, 0)

	var domainSections strings.Builder

	for _, domainData := range rd.Domains {
		targetDomains = append(targetDomains, domainData.Domain)
		totalSubdomains += len(domainData.Subdomains)

		domainParts := strings.Count(domainData.Domain, ".") + 1
		domainSections.WriteString(fmt.Sprintf(`
		<div class="domain-card">
			<div class="domain-head" onclick="toggleDomain(this)">
				<div>
					<h3><span class="carat">▶</span>%s</h3>
					<p>%d subdomains • %s</p>
				</div>
				<span class="chip">investigate</span>
			</div>
			<div class="domain-body" style="display:none;">
				<div class="domain-tools">
					<input type="text" placeholder="Filter within this domain..." oninput="filterTable(this)">
				</div>
				<div class="table-wrap">
					<table class="grid domain-grid">
						<thead>
							<tr>
								<th onclick="sortTable(this,0)">Subdomain</th>
								<th onclick="sortTable(this,1)">Depth</th>
								<th onclick="sortTable(this,2)">Sources</th>
								<th onclick="sortTable(this,3)">Risk</th>
								<th>Tags</th>
							</tr>
						</thead>
						<tbody>`,
			html.EscapeString(domainData.Domain),
			len(domainData.Subdomains),
			domainData.Duration.Round(time.Millisecond).String(),
		))

		for _, sub := range domainData.Subdomains {
			subParts := strings.Count(sub.Host, ".") + 1
			depth := subParts - domainParts
			if depth < 1 {
				depth = 1
			}
			if depth > maxDepth {
				maxDepth = depth
			}

			risk, tags := hostRisk(sub.Host)
			totalRisk += risk
			totalHosts++
			totalSourceLinks += len(sub.Sources)

			lowerHost := strings.ToLower(sub.Host)
			for keyword := range keywordMap {
				if strings.Contains(lowerHost, keyword) {
					keywordMap[keyword]++
				}
			}

			for _, source := range sub.Sources {
				sourceCountMap[source]++
			}

			insightHosts = append(insightHosts, reportInsightHost{
				Domain:      domainData.Domain,
				Host:        sub.Host,
				Depth:       depth,
				RiskScore:   risk,
				Tags:        tags,
				SourceCount: len(sub.Sources),
			})

			var sourcesBuilder strings.Builder
			for _, source := range sub.Sources {
				sourcesBuilder.WriteString(fmt.Sprintf(`<span class="source">%s</span>`, html.EscapeString(source)))
			}

			rowKeywords := strings.ToLower(strings.Join(tags, " ") + " " + sub.Host)

			domainSections.WriteString(fmt.Sprintf(`
							<tr data-host="%s" data-keywords="%s">
								<td class="mono">%s</td>
								<td>%d</td>
								<td>%s</td>
								<td><span class="risk %s">%d</span></td>
								<td>%s</td>
							</tr>`,
				html.EscapeString(strings.ToLower(sub.Host)),
				html.EscapeString(rowKeywords),
				html.EscapeString(sub.Host),
				depth,
				sourcesBuilder.String(),
				riskClass(risk),
				risk,
				tagsHTML(tags),
			))
		}

		domainSections.WriteString(`
						</tbody>
					</table>
				</div>`)

		if len(domainData.Statistics) > 0 {
			domainSections.WriteString(`
				<h4>Source Runtime Stats</h4>
				<div class="table-wrap">
				<table class="grid stats-grid">
					<thead>
						<tr>
							<th>Source</th>
							<th>Duration</th>
							<th>Results</th>
							<th>Requests</th>
							<th>Errors</th>
						</tr>
					</thead>
					<tbody>`)

			statKeys := make([]string, 0, len(domainData.Statistics))
			for source := range domainData.Statistics {
				statKeys = append(statKeys, source)
			}
			sort.Strings(statKeys)

			for _, source := range statKeys {
				stat := domainData.Statistics[source]
				if stat.Skipped {
					continue
				}
				agg := statAgg[source]
				agg.Source = source
				agg.Results += stat.Results
				agg.Requests += stat.Requests
				agg.Errors += stat.Errors
				agg.AvgDurationMs += stat.TimeTaken.Milliseconds()
				statAgg[source] = agg

				errClass := ""
				if stat.Errors > 0 {
					errClass = ` class="bad"`
				}

				domainSections.WriteString(fmt.Sprintf(`<tr><td>%s</td><td>%s</td><td>%d</td><td>%d</td><td%s>%d</td></tr>`,
					html.EscapeString(source),
					stat.TimeTaken.Round(time.Millisecond).String(),
					stat.Results,
					stat.Requests,
					errClass,
					stat.Errors,
				))
			}

			domainSections.WriteString(`
					</tbody>
				</table>
				</div>`)
		}

		domainSections.WriteString(`
			</div>
		</div>`)
	}

	totalSources := len(sourceCountMap)
	avgSourcesPerHost := 0.0
	if totalSubdomains > 0 {
		avgSourcesPerHost = float64(totalSourceLinks) / float64(totalSubdomains)
	}
	avgRisk := 0
	if totalHosts > 0 {
		avgRisk = totalRisk / totalHosts
	}

	sourceCounts := make([]sourceCount, 0, len(sourceCountMap))
	for name, count := range sourceCountMap {
		sourceCounts = append(sourceCounts, sourceCount{Name: name, Count: count})
	}
	sort.Slice(sourceCounts, func(i, j int) bool { return sourceCounts[i].Count > sourceCounts[j].Count })

	healthRows := make([]sourceHealth, 0, len(statAgg))
	for _, entry := range statAgg {
		healthRows = append(healthRows, entry)
	}

	sourceLabels := make([]string, 0, len(sourceCounts))
	sourceValues := make([]string, 0, len(sourceCounts))
	for _, source := range sourceCounts {
		sourceLabels = append(sourceLabels, source.Name)
		sourceValues = append(sourceValues, fmt.Sprintf("%d", source.Count))
	}

	depthMap := make(map[int]int)
	for _, item := range insightHosts {
		depthMap[item.Depth]++
	}
	depthLabels := make([]string, 0, maxDepth)
	depthValues := make([]string, 0, maxDepth)
	for depth := 1; depth <= maxDepth; depth++ {
		depthLabels = append(depthLabels, fmt.Sprintf("Depth %d", depth))
		depthValues = append(depthValues, fmt.Sprintf("%d", depthMap[depth]))
	}

	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Subfinder Intelligence Report</title>
<style>
:root {
	--bg: #0f1020;
	--panel: #1a1c34;
	--panel-soft: #252849;
	--border: #383c66;
	--text: #f3f5ff;
	--muted: #a9afd6;
	--accent: #8f7cff;
	--accent-2: #59d3c2;
	--warn: #ffba6b;
	--bad: #ff6f91;
	--ok: #86f3a6;
	--card-glow: 0 12px 28px rgba(12, 8, 31, 0.35);
}
* { box-sizing: border-box; }
body {
	margin: 0;
	background:
		radial-gradient(circle at 8%% 0%%, #2a1f57 0%%, transparent 38%%),
		radial-gradient(circle at 92%% 16%%, #153b4d 0%%, transparent 36%%),
		linear-gradient(160deg, #121328 0%%, #0f1020 52%%, #14172d 100%%);
	color: var(--text);
	font-family: "Inter", "Avenir Next", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
.container {
	max-width: 1480px;
	margin: 0 auto;
	padding: 26px;
}
.header {
	background: linear-gradient(130deg, rgba(26, 28, 52, 0.96), rgba(33, 23, 61, 0.94));
	border: 1px solid var(--border);
	border-radius: 22px;
	padding: 26px;
	margin-bottom: 20px;
	box-shadow: var(--card-glow);
}
.title {
	margin: 0;
	font-size: 32px;
	font-weight: 800;
	letter-spacing: 0.2px;
	background: linear-gradient(95deg, #c9c2ff, #79ead4);
	-webkit-background-clip: text;
	background-clip: text;
	color: transparent;
}
.subtitle {
	margin: 8px 0 0;
	color: var(--muted);
	font-size: 14px;
}
.meta {
	display: flex;
	gap: 16px;
	flex-wrap: wrap;
	margin-top: 16px;
	font-size: 13px;
	color: var(--muted);
}
.summary {
	display: grid;
	grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
	gap: 12px;
	margin-bottom: 16px;
}
.stat {
	background: var(--panel);
	border: 1px solid var(--border);
	border-radius: 16px;
	padding: 16px;
	box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);
}
.stat .value {
	font-size: 30px;
	font-weight: 700;
	line-height: 1.1;
}
.stat .label {
	margin-top: 6px;
	font-size: 12px;
	color: var(--muted);
	text-transform: uppercase;
	letter-spacing: 0.5px;
}
.actions {
	display: flex;
	gap: 8px;
	flex-wrap: wrap;
	margin-bottom: 14px;
}
button {
	border: 1px solid var(--border);
	background: linear-gradient(180deg, #2a2f57, #24294a);
	color: var(--text);
	padding: 9px 13px;
	border-radius: 12px;
	cursor: pointer;
	font-size: 13px;
	font-weight: 600;
	box-shadow: 0 4px 14px rgba(8, 6, 20, 0.25);
}
button:hover {
	border-color: #8574ef;
	transform: translateY(-1px);
}
.global-search {
	width: 100%%;
	border: 1px solid var(--border);
	border-radius: 12px;
	background: var(--panel);
	color: var(--text);
	padding: 11px 12px;
	margin-bottom: 14px;
}
.grid-2 {
	display: grid;
	grid-template-columns: 1fr 1fr;
	gap: 12px;
	margin-bottom: 14px;
}
.panel {
	background: var(--panel);
	border: 1px solid var(--border);
	border-radius: 16px;
	padding: 16px;
	box-shadow: var(--card-glow);
}
.panel h3 {
	margin: 0 0 10px;
	font-size: 14px;
	color: #b9c0eb;
	text-transform: uppercase;
	letter-spacing: 0.8px;
}
.pills {
	display: flex;
	flex-wrap: wrap;
	gap: 8px;
}
.pill {
	display: inline-flex;
	align-items: center;
	gap: 8px;
	padding: 7px 11px;
	border-radius: 999px;
	font-size: 12px;
	background: #23294d;
	border: 1px solid #4a4f80;
}
.pill strong { color: var(--accent-2); }
.keyword-pill {
	cursor: pointer;
	color: var(--text);
}
.keyword-pill.active {
	border-color: var(--accent-2);
	background: linear-gradient(180deg, #27445b, #1d3449);
}
.keyword-tools {
	display: flex;
	justify-content: space-between;
	align-items: center;
	gap: 8px;
	margin-bottom: 8px;
}
.keyword-tools .muted {
	font-size: 12px;
}
.table-wrap {
	overflow: auto;
	border: 1px solid var(--border);
	border-radius: 12px;
	max-height: 430px;
}
.grid {
	width: 100%%;
	border-collapse: collapse;
	font-size: 13px;
}
.grid th, .grid td {
	padding: 9px 10px;
	border-top: 1px solid #233a5d;
	vertical-align: top;
}
.grid th {
	position: sticky;
	top: 0;
	background: #252a4d;
	color: var(--muted);
	text-transform: uppercase;
	font-size: 11px;
	letter-spacing: 0.5px;
	cursor: pointer;
}
.grid tr:hover td {
	background: rgba(143, 124, 255, 0.12);
}
.mono {
	font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
	word-break: break-all;
}
.tag {
	display: inline-block;
	padding: 2px 8px;
	border: 1px solid #2d4e7d;
	border-radius: 999px;
	margin: 2px 3px 2px 0;
	font-size: 11px;
	color: #b7d7ff;
}
.source {
	display: inline-block;
	padding: 2px 7px;
	border: 1px solid #3e5f89;
	border-radius: 7px;
	margin: 2px;
	font-size: 11px;
	color: #c5dbff;
}
.risk {
	display: inline-block;
	padding: 3px 8px;
	border-radius: 8px;
	font-weight: 700;
	font-size: 12px;
}
.risk.low { background: rgba(138, 245, 143, 0.18); color: var(--ok); }
.risk.medium { background: rgba(255, 180, 84, 0.18); color: var(--warn); }
.risk.high, .risk.critical { background: rgba(255, 107, 138, 0.2); color: var(--bad); }
.ok { color: var(--ok); }
.warn { color: var(--warn); }
.bad { color: var(--bad); }
.domain-card {
	border: 1px solid var(--border);
	border-radius: 16px;
	background: var(--panel);
	margin-bottom: 11px;
	box-shadow: var(--card-glow);
}
.domain-head {
	padding: 15px;
	display: flex;
	justify-content: space-between;
	align-items: center;
	cursor: pointer;
}
.domain-head:hover { background: rgba(143, 124, 255, 0.1); }
.domain-head h3 {
	margin: 0;
	font-size: 17px;
	display: flex;
	align-items: center;
	gap: 8px;
}
.domain-head p {
	margin: 4px 0 0;
	font-size: 12px;
	color: var(--muted);
}
.carat {
	font-size: 10px;
	color: var(--muted);
	transition: transform 0.2s;
}
.domain-head.open .carat { transform: rotate(90deg); }
.chip {
	font-size: 11px;
	padding: 4px 11px;
	border-radius: 999px;
	background: #2a315f;
	color: #c2c8ff;
}
.domain-body {
	padding: 0 14px 14px;
}
.domain-tools input {
	width: 100%%;
	border: 1px solid var(--border);
	background: #1f2443;
	color: var(--text);
	padding: 9px 10px;
	border-radius: 10px;
	margin-bottom: 10px;
}
.chart {
	height: 300px;
}
.footer {
	margin-top: 16px;
	font-size: 12px;
	color: var(--muted);
	text-align: center;
	opacity: 0.9;
}
.muted { color: var(--muted); font-size: 12px; }
@media (max-width: 980px) {
	.grid-2 { grid-template-columns: 1fr; }
}
</style>
</head>
<body>
<div class="container">
	<section class="header">
		<h1 class="title">Subfinder // Recon Board</h1>
		<p class="subtitle">Built for humans: searchable, filterable, and prioritized subdomain intelligence.</p>
		<div class="meta">
			<span>Targets: <strong>%s</strong></span>
			<span>Generated: <strong>%s</strong></span>
			<span>Total Runtime: <strong>%s</strong></span>
		</div>
	</section>

	<section class="summary">
		<div class="stat"><div class="value">%d</div><div class="label">Total Subdomains</div></div>
		<div class="stat"><div class="value">%d</div><div class="label">Target Domains</div></div>
		<div class="stat"><div class="value">%d</div><div class="label">Unique Sources</div></div>
		<div class="stat"><div class="value">%d</div><div class="label">Avg Risk Score</div></div>
		<div class="stat"><div class="value">%.2f</div><div class="label">Avg Sources/Host</div></div>
		<div class="stat"><div class="value">%d</div><div class="label">Max Depth</div></div>
	</section>

	<div class="actions">
		<button onclick="copyAllSubdomains(event)">Copy all subdomains</button>
		<button onclick="downloadCSV()">Export CSV</button>
		<button onclick="expandAll()">Expand all domains</button>
		<button onclick="collapseAll()">Collapse all domains</button>
	</div>
	<input class="global-search" placeholder="Global search across all domain tables" oninput="globalFilter(this.value)" />

	<section class="grid-2">
		<div class="panel">
			<h3>Top Suspect Hosts (by risk score)</h3>
			<div class="table-wrap">
				<table class="grid" id="riskTable">
					<thead><tr><th onclick="sortTable(this,0)">Domain</th><th onclick="sortTable(this,1)">Host</th><th onclick="sortTable(this,2)">Sources</th><th onclick="sortTable(this,3)">Risk</th><th>Tags</th></tr></thead>
					<tbody>%s</tbody>
				</table>
			</div>
		</div>
		<div class="panel">
			<h3>Keyword Signal Density</h3>
			<div class="keyword-tools">
				<span class="muted">Click any keyword to filter all domain rows.</span>
				<button type="button" onclick="clearKeywordFilter()">Clear keyword filter</button>
			</div>
			<div class="pills">%s</div>
			<h3 style="margin-top:14px;">Top Sources by Coverage</h3>
			<div class="table-wrap">
				<table class="grid"><thead><tr><th>Source</th><th>Hosts</th></tr></thead><tbody>%s</tbody></table>
			</div>
		</div>
	</section>

	<section class="grid-2">
		<div class="panel">
			<h3>Results by Source</h3>
			<canvas id="sourceCanvas" class="chart"></canvas>
		</div>
		<div class="panel">
			<h3>Depth Distribution</h3>
			<canvas id="depthCanvas" class="chart"></canvas>
		</div>
	</section>

	<section class="panel" style="margin-bottom:14px;">
		<h3>Source Reliability View</h3>
		<div class="table-wrap">
			<table class="grid" id="healthTable">
				<thead><tr><th onclick="sortTable(this,0)">Source</th><th onclick="sortTable(this,1)">Results</th><th onclick="sortTable(this,2)">Requests</th><th onclick="sortTable(this,3)">Error Rate</th><th onclick="sortTable(this,4)">Avg Duration</th></tr></thead>
				<tbody>%s</tbody>
			</table>
		</div>
	</section>

	<section>
		%s
	</section>

	<div class="footer">Generated by subfinder • %s</div>
</div>
<script>
const COLORS = ['#5cb6ff','#6de4c7','#ffb454','#ff6b8a','#c792ea','#82aaff','#96f0ff','#ff9e64','#8af58f','#f7768e'];

function drawBar(canvasId, labels, values) {
	const canvas = document.getElementById(canvasId);
	if (!canvas) return;
	const ctx = canvas.getContext('2d');
	const dpr = window.devicePixelRatio || 1;
	const width = canvas.parentElement.clientWidth - 10;
	const height = 300;
	canvas.width = width * dpr;
	canvas.height = height * dpr;
	canvas.style.width = width + 'px';
	canvas.style.height = height + 'px';
	ctx.scale(dpr, dpr);
	ctx.clearRect(0,0,width,height);
	if (!labels.length) return;
	const max = Math.max(...values, 1);
	const maxBars = Math.min(labels.length, 14);
	const barGap = 8;
	const chartLeft = 128;
	const barHeight = Math.max(10, (height - 30 - (maxBars * barGap)) / maxBars);
	for (let i = 0; i < maxBars; i++) {
		const y = 12 + i * (barHeight + barGap);
		const barWidth = ((width - chartLeft - 32) * values[i]) / max;
		ctx.fillStyle = COLORS[i %% COLORS.length];
		ctx.beginPath();
		ctx.roundRect(chartLeft, y, Math.max(2, barWidth), barHeight, 4);
		ctx.fill();
		ctx.fillStyle = '#9db7db';
		ctx.font = '12px sans-serif';
		ctx.textAlign = 'right';
		ctx.fillText(labels[i], chartLeft - 8, y + barHeight - 2);
		ctx.textAlign = 'left';
		ctx.fillStyle = '#dce9ff';
		ctx.fillText(String(values[i]), chartLeft + barWidth + 6, y + barHeight - 2);
	}
}

function drawDonut(canvasId, labels, values) {
	const canvas = document.getElementById(canvasId);
	if (!canvas) return;
	const ctx = canvas.getContext('2d');
	const dpr = window.devicePixelRatio || 1;
	const width = canvas.parentElement.clientWidth - 10;
	const height = 300;
	canvas.width = width * dpr;
	canvas.height = height * dpr;
	canvas.style.width = width + 'px';
	canvas.style.height = height + 'px';
	ctx.scale(dpr, dpr);
	ctx.clearRect(0,0,width,height);
	const total = values.reduce((a,b)=>a+b,0);
	if (!labels.length || total === 0) return;

	const cx = width / 2;
	const cy = height / 2;
	const outer = Math.min(width, height) * 0.34;
	const inner = outer * 0.6;
	let angle = -Math.PI / 2;

	for (let i = 0; i < labels.length; i++) {
		const slice = (values[i] / total) * Math.PI * 2;
		ctx.beginPath();
		ctx.arc(cx, cy, outer, angle, angle + slice);
		ctx.arc(cx, cy, inner, angle + slice, angle, true);
		ctx.closePath();
		ctx.fillStyle = COLORS[i %% COLORS.length];
		ctx.fill();

		if (slice > 0.25) {
			const mid = angle + slice / 2;
			const lx = cx + (outer + 16) * Math.cos(mid);
			const ly = cy + (outer + 16) * Math.sin(mid);
			ctx.fillStyle = '#9db7db';
			ctx.font = '12px sans-serif';
			ctx.textAlign = mid > Math.PI/2 && mid < Math.PI*1.5 ? 'right' : 'left';
			ctx.fillText(labels[i] + ' (' + values[i] + ')', lx, ly);
		}
		angle += slice;
	}
	ctx.fillStyle = '#dce9ff';
	ctx.font = 'bold 22px sans-serif';
	ctx.textAlign = 'center';
	ctx.fillText(String(total), cx, cy + 4);
	ctx.fillStyle = '#8ea5c9';
	ctx.font = '11px sans-serif';
	ctx.fillText('hosts', cx, cy + 20);
}

const sourceLabels = [%s];
const sourceValues = [%s].map(Number);
const depthLabels = [%s];
const depthValues = [%s].map(Number);

function renderCharts() {
	drawBar('sourceCanvas', sourceLabels, sourceValues);
	drawDonut('depthCanvas', depthLabels, depthValues);
}
renderCharts();
window.addEventListener('resize', renderCharts);

let activeKeyword = '';

function applyAllFilters() {
	const globalInput = document.querySelector('.global-search');
	const globalTerm = globalInput ? globalInput.value.toLowerCase().trim() : '';

	document.querySelectorAll('.domain-card').forEach(card => {
		const body = card.querySelector('.domain-body');
		const localInput = card.querySelector('.domain-tools input');
		const localTerm = localInput ? localInput.value.toLowerCase().trim() : '';
		const rows = card.querySelectorAll('.domain-grid tbody tr');
		let hasVisible = false;

		rows.forEach(row => {
			const host = (row.dataset.host || '').toLowerCase();
			const rowText = row.textContent.toLowerCase();
			const rowKeywords = (row.dataset.keywords || '').toLowerCase();

			const matchGlobal = globalTerm === '' || host.includes(globalTerm) || rowText.includes(globalTerm);
			const matchLocal = localTerm === '' || host.includes(localTerm) || rowText.includes(localTerm);
			const matchKeyword = activeKeyword === '' || rowKeywords.includes(activeKeyword);

			const show = matchGlobal && matchLocal && matchKeyword;
			row.style.display = show ? '' : 'none';
			if (show) {
				hasVisible = true;
			}
		});

		if ((globalTerm || activeKeyword) && hasVisible) {
			body.style.display = 'block';
			card.querySelector('.domain-head').classList.add('open');
		}
	});

	const riskRows = document.querySelectorAll('#riskTable tbody tr');
	riskRows.forEach(row => {
		const rowText = row.textContent.toLowerCase();
		const rowKeywords = (row.dataset.keywords || '').toLowerCase();
		const matchGlobal = globalTerm === '' || rowText.includes(globalTerm);
		const matchKeyword = activeKeyword === '' || rowKeywords.includes(activeKeyword);
		row.style.display = matchGlobal && matchKeyword ? '' : 'none';
	});
}

function toggleDomain(head) {
	const body = head.nextElementSibling;
	const open = body.style.display !== 'none';
	body.style.display = open ? 'none' : 'block';
	head.classList.toggle('open', !open);
}

function expandAll() {
	document.querySelectorAll('.domain-body').forEach(el => el.style.display = 'block');
	document.querySelectorAll('.domain-head').forEach(el => el.classList.add('open'));
}

function collapseAll() {
	document.querySelectorAll('.domain-body').forEach(el => el.style.display = 'none');
	document.querySelectorAll('.domain-head').forEach(el => el.classList.remove('open'));
}

function filterTable(input) {
	applyAllFilters();
}

function globalFilter(term) {
	applyAllFilters();
}

function applyKeywordFilter(keyword) {
	const value = (keyword || '').toLowerCase();
	activeKeyword = activeKeyword === value ? '' : value;
	document.querySelectorAll('.keyword-pill').forEach(pill => {
		pill.classList.toggle('active', pill.dataset.keyword === activeKeyword);
	});
	applyAllFilters();
}

function clearKeywordFilter() {
	activeKeyword = '';
	document.querySelectorAll('.keyword-pill').forEach(pill => pill.classList.remove('active'));
	applyAllFilters();
}

function sortTable(th, colIdx) {
	const table = th.closest('table');
	const tbody = table.querySelector('tbody');
	const rows = Array.from(tbody.rows);
	const asc = th.dataset.asc !== '1';
	th.dataset.asc = asc ? '1' : '0';

	rows.sort((a, b) => {
		const av = a.cells[colIdx].textContent.trim();
		const bv = b.cells[colIdx].textContent.trim();
		const an = parseFloat(av.replace(/[^0-9.-]/g, ''));
		const bn = parseFloat(bv.replace(/[^0-9.-]/g, ''));
		if (!Number.isNaN(an) && !Number.isNaN(bn)) return asc ? an - bn : bn - an;
		return asc ? av.localeCompare(bv) : bv.localeCompare(av);
	});
	rows.forEach(row => tbody.appendChild(row));
}

function copyAllSubdomains(ev) {
	const values = [];
	document.querySelectorAll('.domain-grid .mono').forEach(cell => values.push(cell.textContent.trim()));
	navigator.clipboard.writeText(values.join('\n')).then(() => {
		const btn = ev.target;
		const txt = btn.textContent;
		btn.textContent = 'Copied';
		setTimeout(() => btn.textContent = txt, 1200);
	});
}

function downloadCSV() {
	let csv = 'Domain,Subdomain,Depth,Sources,Risk,Tags\n';
	document.querySelectorAll('.domain-card').forEach(card => {
		const domain = card.querySelector('.domain-head h3').textContent.replace('▶', '').trim();
		card.querySelectorAll('.domain-grid tbody tr').forEach(row => {
			if (row.style.display === 'none') return;
			const sub = row.cells[0].textContent.trim();
			const depth = row.cells[1].textContent.trim();
			const src = row.cells[2].textContent.replace(/\s+/g, ' ').trim();
			const risk = row.cells[3].textContent.trim();
			const tags = row.cells[4].textContent.replace(/\s+/g, ' ').trim();
			csv += '"' + domain + '","' + sub + '","' + depth + '","' + src + '","' + risk + '","' + tags + '"\n';
		});
	});
	const blob = new Blob([csv], { type: 'text/csv' });
	const a = document.createElement('a');
	a.href = URL.createObjectURL(blob);
	a.download = 'subfinder-intelligence-report.csv';
	a.click();
}
</script>
</body>
</html>`,
		html.EscapeString(strings.Join(targetDomains, ", ")),
		rd.EndTime.Format("2006-01-02 15:04:05 MST"),
		totalDuration.Round(time.Second).String(),
		totalSubdomains,
		len(rd.Domains),
		totalSources,
		avgRisk,
		avgSourcesPerHost,
		maxDepth,
		riskTableHTML(insightHosts, 100),
		topKeywordHTML(keywordMap, 12),
		topSourcesHTML(sourceCounts, 20),
		sourceHealthHTML(healthRows, 20),
		domainSections.String(),
		rd.EndTime.Format("2006-01-02 15:04:05 MST"),
		toQuotedJSArray(sourceLabels),
		strings.Join(sourceValues, ","),
		toQuotedJSArray(depthLabels),
		strings.Join(depthValues, ","),
	)

	if _, err = f.WriteString(htmlContent); err != nil {
		return fmt.Errorf("could not write report: %w", err)
	}

	gologger.Info().Msgf("HTML report saved to %s\n", outputPath)
	return nil
}
