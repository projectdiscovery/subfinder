# Testing Guide for Timeout Fix

## Quick Test

### Test 1: Basic Timeout Functionality
```bash
# Test with a short timeout
subfinder -d erlang.org -timeout 5 -silent

# Should complete within ~5 seconds
# Previously: Could take 30+ seconds inconsistently
```

### Test 2: Consistency Across Multiple Runs
```bash
# Run 10 times and measure consistency
for i in {1..10}; do
    echo "=== Run $i ==="
    time subfinder -d erlang.org -timeout 5 -silent | wc -l
    echo ""
done

# Expected: All runs should complete in similar time (~5-6 seconds)
# Previously: Times would vary wildly (5s, 15s, 30s, etc.)
```

### Test 3: Very Short Timeout
```bash
# Test with 1 second timeout
subfinder -d example.com -timeout 1 -v

# Should timeout quickly and show timeout errors
# Previously: Would sometimes ignore the timeout
```

## Detailed Testing

### Test 4: Compare Before and After

#### Before (Old Version):
```bash
# Clone old version
git clone https://github.com/projectdiscovery/subfinder.git subfinder-old
cd subfinder-old
git checkout v2.7.0
go build ./cmd/subfinder

# Test
time ./subfinder -d erlang.org -timeout 5 -silent
# Result: Inconsistent timing, sometimes hangs
```

#### After (Fixed Version):
```bash
# Clone fixed version
git clone https://github.com/1234-ad/subfinder.git subfinder-new
cd subfinder-new
git checkout fix/timeout-flag-consistency
go build ./cmd/subfinder

# Test
time ./subfinder -d erlang.org -timeout 5 -silent
# Result: Consistent ~5 second timeout
```

### Test 5: Timeout with Different Values

```bash
# Test various timeout values
for timeout in 1 3 5 10 30; do
    echo "Testing timeout: ${timeout}s"
    time subfinder -d example.com -timeout $timeout -silent
    echo "---"
done

# Expected: Each run should respect its timeout value
```

### Test 6: Timeout with Max-Time

```bash
# Test interaction between timeout and max-time
subfinder -d example.com -timeout 5 -max-time 1 -v

# Expected: Should stop after 1 minute (max-time)
# Individual source requests should timeout after 5 seconds
```

## Automated Test Script

Save this as `test_timeout.sh`:

```bash
#!/bin/bash

echo "=== Subfinder Timeout Fix Test Suite ==="
echo ""

# Test 1: Basic timeout
echo "Test 1: Basic timeout (5s)"
start=$(date +%s)
subfinder -d erlang.org -timeout 5 -silent > /dev/null 2>&1
end=$(date +%s)
duration=$((end - start))
echo "Duration: ${duration}s"
if [ $duration -le 10 ]; then
    echo "✅ PASS: Completed within expected time"
else
    echo "❌ FAIL: Took too long"
fi
echo ""

# Test 2: Consistency test
echo "Test 2: Consistency across 5 runs"
times=()
for i in {1..5}; do
    start=$(date +%s)
    subfinder -d erlang.org -timeout 5 -silent > /dev/null 2>&1
    end=$(date +%s)
    duration=$((end - start))
    times+=($duration)
    echo "Run $i: ${duration}s"
done

# Calculate variance
sum=0
for t in "${times[@]}"; do
    sum=$((sum + t))
done
avg=$((sum / 5))
echo "Average: ${avg}s"

# Check if all times are within 3 seconds of average
consistent=true
for t in "${times[@]}"; do
    diff=$((t - avg))
    diff=${diff#-}  # absolute value
    if [ $diff -gt 3 ]; then
        consistent=false
    fi
done

if [ "$consistent" = true ]; then
    echo "✅ PASS: Consistent timing"
else
    echo "❌ FAIL: Inconsistent timing"
fi
echo ""

# Test 3: Very short timeout
echo "Test 3: Very short timeout (1s)"
start=$(date +%s)
subfinder -d example.com -timeout 1 -silent > /dev/null 2>&1
end=$(date +%s)
duration=$((end - start))
echo "Duration: ${duration}s"
if [ $duration -le 5 ]; then
    echo "✅ PASS: Respected short timeout"
else
    echo "❌ FAIL: Did not respect timeout"
fi
echo ""

echo "=== Test Suite Complete ==="
```

Run with:
```bash
chmod +x test_timeout.sh
./test_timeout.sh
```

## Expected Results

### ✅ Success Criteria:

1. **Timeout Respected**: Requests should timeout within the specified time (±2 seconds for overhead)
2. **Consistency**: Multiple runs with same timeout should have similar durations
3. **No Hangs**: No requests should hang indefinitely
4. **Error Handling**: Timeout errors should be logged properly in verbose mode

### Example Output:

```
=== Subfinder Timeout Fix Test Suite ===

Test 1: Basic timeout (5s)
Duration: 6s
✅ PASS: Completed within expected time

Test 2: Consistency across 5 runs
Run 1: 6s
Run 2: 5s
Run 3: 6s
Run 4: 5s
Run 5: 6s
Average: 5s
✅ PASS: Consistent timing

Test 3: Very short timeout (1s)
Duration: 2s
✅ PASS: Respected short timeout

=== Test Suite Complete ===
```

## Manual Verification

### Check for Timeout Errors in Verbose Mode:

```bash
subfinder -d example.com -timeout 1 -v 2>&1 | grep -i timeout

# Should see timeout-related messages like:
# [WRN] Encountered an error with source xyz: context deadline exceeded
```

### Monitor Network Activity:

```bash
# In one terminal, start subfinder with short timeout
subfinder -d example.com -timeout 3 -v

# In another terminal, monitor connections
watch -n 1 'netstat -an | grep ESTABLISHED | wc -l'

# Should see connections drop after ~3 seconds
```

## Performance Comparison

### Benchmark Script:

```bash
#!/bin/bash

echo "Benchmarking timeout performance..."

# Test with different timeout values
for timeout in 1 5 10 30; do
    echo "Timeout: ${timeout}s"
    
    # Run 3 times and average
    total=0
    for i in {1..3}; do
        start=$(date +%s%N)
        subfinder -d erlang.org -timeout $timeout -silent > /dev/null 2>&1
        end=$(date +%s%N)
        duration=$(( (end - start) / 1000000 ))  # Convert to milliseconds
        total=$((total + duration))
    done
    
    avg=$((total / 3))
    echo "Average: ${avg}ms"
    echo ""
done
```

## Troubleshooting

### If Tests Fail:

1. **Check Go Version**: Ensure Go 1.19+ is installed
   ```bash
   go version
   ```

2. **Rebuild**: Clean build the binary
   ```bash
   go clean
   go build ./cmd/subfinder
   ```

3. **Check Network**: Ensure internet connectivity
   ```bash
   ping -c 3 google.com
   ```

4. **Verbose Mode**: Run with `-v` to see detailed errors
   ```bash
   subfinder -d example.com -timeout 5 -v
   ```

## Integration Tests

### Test with CI/CD:

```yaml
# .github/workflows/test-timeout.yml
name: Test Timeout Fix

on: [push, pull_request]

jobs:
  test-timeout:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: '1.21'
      
      - name: Build
        run: go build ./cmd/subfinder
      
      - name: Test timeout consistency
        run: |
          for i in {1..5}; do
            timeout 10 ./subfinder -d erlang.org -timeout 5 -silent
          done
      
      - name: Test short timeout
        run: |
          timeout 5 ./subfinder -d example.com -timeout 1 -silent
```

## Conclusion

This fix ensures that the `-timeout` flag works consistently and reliably across all runs. The timeout is now properly enforced at multiple levels (connection, TLS, request) and respects context cancellation.
