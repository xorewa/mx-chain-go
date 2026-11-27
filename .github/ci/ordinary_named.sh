#!/usr/bin/env bash
# Reviewed ordinary roots only. Separate receipts; never feed the hybrid gate.
set -euo pipefail
mode=${1:?normal or race required}
output=${2:?new result directory required}
case "$mode" in
    normal) flags=() ;;
    race) flags=(-race) ;;
    *) exit 2 ;;
esac
if ! mkdir "$output" 2>/dev/null; then
    # CI uploads portable/ even when this step fails. Refuse a reused output
    # directory but preserve its previous portable artifacts outside that path.
    # Never overwrite an archive or alter prior raw receipts/profiles.
    if [[ -d "$output" && ! -L "$output" && ( -e "$output/portable" || -L "$output/portable" ) ]]; then
        if ! prior=$(mktemp -d "$output/.prior-portable.XXXXXXXX" 2>/dev/null) || \
            ! mv -- "$output/portable" "$prior/portable" 2>/dev/null; then
            printf '%s\n' 'ordinary named output collision; prior portable archive failed' >&2
            exit 1
        fi
    fi
    printf '%s\n' 'ordinary named output is not new; no tests executed' >&2
    exit 1
fi
mkdir "$output/portable"
failed=0

run_selected_group() {
    local id=$1 package=$2 selector=$3
    shift 3
    local status=0 receipt_status=0 profile_status=2 publish_status=2 name
    local -a expected=()
    for name in "$@"; do expected+=(--expect "$name"); done
    # Exact root selection; each stream is bound to one package and all named passes.
    go test "${flags[@]}" -json -count=1 -covermode=atomic \
        -coverprofile="$output/$id.cover" -run="$selector" "$package" \
        > "$output/$id.events.jsonl" || status=$?
    printf '%s\n' "$status" > "$output/portable/$id.test.exit"
    python3 -B .github/ci/named_test_receipt.py \
        --events "$output/$id.events.jsonl" \
        --package "github.com/multiversx/mx-chain-go/${package#./}" \
        "${expected[@]}" --exit-code "$status" \
        > "$output/$id.receipt.json" || receipt_status=$?
    printf '%s\n' "$receipt_status" > "$output/portable/$id.receipt.exit"
    # A named PASS does not prove that coverage was produced. Status 2 means
    # not attempted; keep separate statuses and never publish half a pair.
    if (( status == 0 && receipt_status == 0 )); then
        profile_status=1
        if python3 -B .github/ci/ordinary_package_profile.py --profile "$output/$id.cover" \
            --package "github.com/multiversx/mx-chain-go/${package#./}"; then
            profile_status=0
            if cp "$output/$id.receipt.json" "$output/$id.cover" "$output/portable/"; then
                publish_status=0
            else
                publish_status=1
                rm -f -- "$output/portable/$id.receipt.json" "$output/portable/$id.cover" || :
            fi
        fi
    fi
    printf '%s\n' "$profile_status" > "$output/portable/$id.profile.exit"
    printf '%s\n' "$publish_status" > "$output/portable/$id.publish.exit"
    if (( status != 0 || receipt_status != 0 || profile_status != 0 || publish_status != 0 )); then
        failed=1
    fi
}

run_group() {
    local id=$1 package=$2 selector
    shift 2
    selector=$(IFS='|'; printf '%s' "$*")
    run_selected_group "$id" "$package" "^($selector)$" "$@"
}

run_nested_group() {
    local id=$1 package=$2 root=$3 selector name
    shift 3
    local -a names=()
    selector=$(IFS='|'; printf '%s' "$*")
    for name in "$@"; do names+=("$root/$name"); done
    run_selected_group "$id" "$package" "^($root)$/^($selector)$" "${names[@]}"
}

# File-list diagnostics deliberately compile only the reviewed source/fixture files.
# Keep raw absolute-path profiles local; only the strict normalizer can publish them.
run_file_group() {
    local id=$1 directory=$2 selector=$3 coverpkg=$4
    shift 4
    local checkout absolute status=0 receipt_status=0 profile_status=2 publish_status=2
    local -a expected=() coverage=()
    while [[ $1 != -- ]]; do expected+=(--expect "$1"); shift; done
    shift
    if [[ -n "$coverpkg" ]]; then coverage=(-coverpkg="$coverpkg"); fi
    checkout=$(pwd -P)
    absolute=$(cd "$output" && pwd -P)
    (cd "$checkout/$directory" && go test -mod=readonly -count=1 -timeout=70s -json \
        -covermode=atomic -coverprofile="$absolute/$id.raw.cover" "${flags[@]}" \
        "${coverage[@]}" -run "$selector" "$@") \
        > "$output/$id.events.jsonl" || status=$?
    printf '%s\n' "$status" > "$output/portable/$id.test.exit"
    python3 -B .github/ci/named_test_receipt.py \
        --events "$output/$id.events.jsonl" --package command-line-arguments \
        "${expected[@]}" --exit-code "$status" \
        > "$output/$id.named-receipt.json" || receipt_status=$?
    printf '%s\n' "$receipt_status" > "$output/portable/$id.receipt.exit"
    if (( status == 0 && receipt_status == 0 )); then
        profile_status=0
        python3 -B .github/coverage/ordinary/file-list-portable/normalize.py \
            --profile "$output/$id.raw.cover" --checkout "$checkout" \
            --group "$id" --mode "$mode" --output "$output/$id.normalized" || profile_status=$?
        if (( profile_status == 0 )); then
            if cp "$output/$id.normalized/coverage.cover" "$output/portable/$id.cover" && \
                cp "$output/$id.normalized/receipt.json" "$output/portable/$id.normalization.json" && \
                cp "$output/$id.named-receipt.json" "$output/portable/$id.named-receipt.json"; then
                publish_status=0
            else
                publish_status=1
                rm -f -- "$output/portable/$id.cover" "$output/portable/$id.normalization.json" \
                    "$output/portable/$id.named-receipt.json" || :
            fi
        fi
    fi
    printf '%s\n' "$profile_status" > "$output/portable/$id.profile.exit"
    printf '%s\n' "$publish_status" > "$output/portable/$id.publish.exit"
    if (( status != 0 || receipt_status != 0 || profile_status != 0 || publish_status != 0 )); then
        failed=1
    fi
}

run_group writer ./api/logs TestQualSP281COrdinaryLogWriterDistinctPayloadOrder
run_group presenter ./cmd/termui/presenter TestQualSP281COrdinaryPresenterConcurrentCounters TestQualSP281COrdinaryPresenterCounterArithmetic TestQualSP281COrdinaryPresenterValueStoreRoundTrip
run_group drawable ./cmd/termui/view/termuic/termuiRenders TestQualSP281COrdinaryDrawableContainerLayout TestQualSP281COrdinaryDrawableContainerSparseResize
run_group sort ./common/compatibility TestQualSP281COrdinarySortStringMultiplicity TestQualSP281COrdinarySortModerateStringList TestQualSP218OrdinarySortRecordAssociation
run_group channel ./common/errChan TestQualSP281COrdinaryErrChanGracefulCloseRetainsValue TestQualSP281COrdinaryErrChanPublicRoundTripReuse
run_group logging ./common/logging TestQualSP281COrdinaryErrorLogRecord
run_group disabled-statistics ./common/statistics/disabled TestQualSP281COrdinaryDisabledStatisticsReports
run_group memory-display ./common/statistics/machine TestQualSP281COrdinaryMachineMemoryReport
run_nested_group time-display ./ntp TestQualSP281COrdinaryTimeDisplay zero_fraction leading_fraction_zeroes full_fraction
run_group presenter-display ./cmd/termui/presenter TestPresenterStatusHandler_GetAppVersion TestPresenterStatusHandler_GetNodeName TestPresenterStatusHandler_GetCpuLoadPercent TestPresenterStatusHandler_GetMemLoadPercent TestPresenterStatusHandler_GetTotalMem TestPresenterStatusHandler_GetMemUsedByNode TestPresenterStatusHandler_CheckSoftwareVersion TestPresenterStatusHandler_CheckSoftwareVersionNeedUpdate TestPresenterStatusHandler_GetLogLine TestPresenterStatusHandler_GetNodeNameShouldReturnDefaultName TestPresenterStatusHandler_GetNetworkRecvPercent TestPresenterStatusHandler_GetNetworkRecvBps TestPresenterStatusHandler_GetNetworkRecvBpsPeak TestPresenterStatusHandler_GetNetworkSentPercent TestPresenterStatusHandler_GetNetworkSentBps TestPresenterStatusHandler_GetNetworkSentBpsPeak TestPresenterStatusHandler_GetNetworkSendBytesInEpoch TestPresenterStatusHandler_GetNetworkReceivedBytesInEpoch
run_nested_group label-fit ./cmd/termui/view/termuic/termuiRenders TestQualSP281COrdinaryStatusLabelFit wide_pane_retains_label compact_pane_adds_ellipsis minimum_pane_leaves_label_blank
run_nested_group log-layout ./cmd/termui/view/termuic/termuiRenders TestWidgetsRender_prepareLogLines equal_size_should_return_the_same_slice should_trim small_size_should_return_empty
run_group disabled-status ./common/disabled TestAppStatusHandler_MethodsShouldNotPanic
run_group statistics-report ./common/statistics TestQualSP218OrdinaryStatisticsReportLabels
run_file_group assessment_report_boundary cmd/assessment/benchmarks '^(TestQualSP281COrdinaryAssessmentReportBoundary)$/^(empty_report_retains_total|single_report_retains_fractional_duration)$' '' TestQualSP281COrdinaryAssessmentReportBoundary/empty_report_retains_total TestQualSP281COrdinaryAssessmentReportBoundary/single_report_retains_fractional_duration -- results.go results_test.go qual_sp281c_ordinary_assessment_report_test.go
run_file_group host_display_wrap common/hostParameters '^(TestQualSP281COrdinaryHostDisplayWrap|TestHostInfo_ToDisplayTable|TestHostInfo_ToStrings|TestQualSP281COrdinaryHostDisplayEmptyFlags)$' '' TestQualSP281COrdinaryHostDisplayWrap TestHostInfo_ToDisplayTable TestHostInfo_ToStrings TestQualSP281COrdinaryHostDisplayEmptyFlags -- hostInfo.go hostInfo_test.go qual_sp281c_ordinary_host_display_wrap_test.go
run_file_group memory_display_units common/statistics/osLevel '^(TestQualSP281COrdinaryMemoryDisplayUnits)$' 'command-line-arguments,github.com/multiversx/mx-chain-core-go/core' TestQualSP281COrdinaryMemoryDisplayUnits -- memStats.go errors.go qual_sp281c_ordinary_memory_display_units_test.go
run_file_group assessment_existing cmd/assessment/benchmarks '^(TestTestResults_ToDisplayTable|TestTestResults_ToStrings|TestQualSP218OrdinaryAssessmentOrderedRows|TestQualSP218OrdinaryAssessmentRepeatedRowLabels)$' '' TestTestResults_ToDisplayTable TestTestResults_ToStrings TestQualSP218OrdinaryAssessmentOrderedRows TestQualSP218OrdinaryAssessmentRepeatedRowLabels -- results.go results_test.go qual_sp218_lane_f_ordinary_assessment_order_test.go qual_sp218_lane_f_ordinary_assessment_association_test.go
exit "$failed"
