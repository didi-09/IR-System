#!/bin/bash
# Cleanup temporary and test files from IR-System

echo "=========================================="
echo "CLEANING UP TEMPORARY FILES"
echo "=========================================="
echo ""

# Files to remove (test scripts and debug files)
TEST_FILES=(
    "debug_agent.py"
    "debug_detection.py"
    "check_detection.py"
    "test_api.py"
    "test_dashboard_enhancements.sh"
    "test_dashboard_generalization.sh"
    "test_definitive.py"
    "test_full_integration.py"
    "test_journald_live.py"
    "test_multi_source_monitoring.py"
    "test_subprocess_direct.py"
    "trace_agent_to_api.py"
    "final_test.sh"
    "quick_test_detection.sh"
    "realtime_test.sh"
    "run_debug_test.sh"
    "simple_test.sh"
    "test_log_generation.sh"
)

cd /home/kali/IR-Project/IR-System

echo "Files to be removed:"
for file in "${TEST_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "  - $file"
    fi
done

echo ""
echo "Files to KEEP:"
echo "  - generate_realtime_events.sh (useful for testing)"
echo "  - start_real_mode.sh (production startup script)"
echo "  - simulate_realistic_attack.py (demo purposes)"
echo "  - simulate_data_stream.py (demo purposes)"
echo ""
read -p "Proceed with cleanup? (y/n): " confirm

if [ "$confirm" = "y" ]; then
    echo ""
    echo "Removing files..."
    for file in "${TEST_FILES[@]}"; do
        if [ -f "$file" ]; then
            rm "$file"
            echo "  ✓ Removed $file"
        fi
    done
    
    echo ""
    echo "✅ Cleanup complete!"
    echo ""
    echo "Remaining files:"
    ls -1 *.py *.sh 2>/dev/null | grep -v "__pycache__"
else
    echo "Cleanup cancelled."
fi
