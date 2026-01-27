#!/bin/bash
# Test for file descriptor leaks during fuzzing

echo "Test 2/3: Checking file descriptor leaks over 60 seconds..."

# Start fuzzer in background with enough runs to last 60+ seconds
# Run minimal.bin 100000 times which should take about 70-80 seconds
./build/curl_fuzzer_cli -detect_leaks=0 -runs=100000 corpora/curl_cli_test/minimal.bin >/dev/null 2>&1 &
FUZZ_PID=$!

# Wait for fuzzer to actually start
sleep 1

# Monitor FD count every 3 seconds
echo "Fuzzer PID: $FUZZ_PID"
echo "Monitoring FD count (should remain stable, not increase monotonically)..."

FD_SAMPLES=()
for i in {1..20}; do
    if [ -d "/proc/$FUZZ_PID/fd" ]; then
        FD_COUNT=$(ls /proc/$FUZZ_PID/fd 2>/dev/null | wc -l)
        FD_SAMPLES+=($FD_COUNT)
        echo "Sample $i ($(($i * 3))s): FD count = $FD_COUNT"
    else
        echo "Sample $i: Process finished"
        break
    fi
    sleep 3
done

# Wait for fuzzer to complete
wait $FUZZ_PID

# Analyze results
echo ""
echo "FD count samples: ${FD_SAMPLES[@]}"
if [ ${#FD_SAMPLES[@]} -gt 2 ]; then
    MIN_FD=${FD_SAMPLES[0]}
    MAX_FD=${FD_SAMPLES[0]}
    for fd in "${FD_SAMPLES[@]}"; do
        [ $fd -lt $MIN_FD ] && MIN_FD=$fd
        [ $fd -gt $MAX_FD ] && MAX_FD=$fd
    done
    echo "Min FD count: $MIN_FD"
    echo "Max FD count: $MAX_FD"
    FD_RANGE=$((MAX_FD - MIN_FD))
    echo "FD count range: $FD_RANGE"

    if [ $FD_RANGE -le 5 ]; then
        echo "✓ PASS: FD count stable (range <= 5)"
    else
        echo "✗ FAIL: FD count increased significantly (range > 5)"
        exit 1
    fi
else
    echo "Not enough samples collected"
fi
