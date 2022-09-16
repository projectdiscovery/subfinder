package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/logrusorgru/aurora"

	"github.com/projectdiscovery/subfinder/v2/pkg/testutils"
)

var (
	debug        = os.Getenv("DEBUG") == "true"
	githubAction = os.Getenv("GH_ACTION") == "true"
	customTests  = os.Getenv("TESTS")

	success = aurora.Green("[✓]").String()
	failed  = aurora.Red("[✘]").String()

	sourceTests = map[string]testutils.TestCase{
		"dnsrepo": dnsrepoTestcases{},
	}
)

func main() {
	failedTestCases := runTests(toMap(toSlice(customTests)))

	if len(failedTestCases) > 0 {
		if githubAction {
			debug = true
			fmt.Println("::group::Failed integration tests in debug mode")
			_ = runTests(failedTestCases)
			fmt.Println("::endgroup::")
		}
		os.Exit(1)
	}
}

func runTests(customTestCases map[string]struct{}) map[string]struct{} {
	failedTestCases := map[string]struct{}{}

	for source, testCase := range sourceTests {
		if len(customTestCases) == 0 {
			fmt.Printf("Running test cases for %q source\n", aurora.Blue(source))
		}
		if err, failedTemplatePath := execute(source, testCase); err != nil {
			failedTestCases[failedTemplatePath] = struct{}{}
		}
	}
	return failedTestCases
}

func execute(source string, testCase testutils.TestCase) (error, string) {
	if err := testCase.Execute(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s Test \"%s\" failed: %s\n", failed, source, err)
		return err, source
	}

	fmt.Printf("%s Test \"%s\" passed!\n", success, source)
	return nil, ""
}

func expectResultsGreaterThanCount(results []string, expectedNumber int) error {
	if len(results) > expectedNumber {
		return nil
	}
	return fmt.Errorf("incorrect number of results: expected a result greater than %d,but got %d", expectedNumber, len(results))
}
func toSlice(value string) []string {
	if strings.TrimSpace(value) == "" {
		return []string{}
	}

	return strings.Split(value, ",")
}

func toMap(slice []string) map[string]struct{} {
	result := make(map[string]struct{}, len(slice))
	for _, value := range slice {
		if _, ok := result[value]; !ok {
			result[value] = struct{}{}
		}
	}
	return result
}
