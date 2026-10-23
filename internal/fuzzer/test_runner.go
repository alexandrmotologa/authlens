package fuzzer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TestResult captures the response to an adversarial token probe.
type TestResult struct {
	VectorID     string `json:"vector_id"`
	VectorName   string `json:"vector_name"`
	Category     string `json:"category"`
	Severity     string `json:"severity"`
	StatusCode   int    `json:"status_code"`
	StatusText   string `json:"status_text"`
	Passed       bool   `json:"passed"`
	Verdict      string `json:"verdict"` // "SECURE" (rejected), "VULNERABLE" (accepted), "ERROR"
	DurationMs   int64  `json:"duration_ms"`
	Snippet      string `json:"snippet"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// SuiteReport contains aggregated findings from the backend security audit.
type SuiteReport struct {
	TargetURL  string       `json:"target_url"`
	Method     string       `json:"method"`
	Timestamp  time.Time    `json:"timestamp"`
	TotalTests int          `json:"total_tests"`
	Passed     int          `json:"passed"`
	Failed     int          `json:"failed"`
	Errors     int          `json:"errors"`
	ScorePct   float64      `json:"score_pct"`
	Results    []TestResult `json:"results"`
}

// RunSuite executes all attack vectors against a specified backend API endpoint.
func RunSuite(ctx context.Context, targetURL, method, headerFormat string, vectors []AttackVector) *SuiteReport {
	if method == "" {
		method = "GET"
	}
	if headerFormat == "" {
		headerFormat = "Authorization: Bearer {{token}}"
	}

	report := &SuiteReport{
		TargetURL:  targetURL,
		Method:     method,
		Timestamp:  time.Now().UTC(),
		TotalTests: len(vectors),
		Results:    make([]TestResult, 0, len(vectors)),
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	for _, v := range vectors {
		res := testSingleVector(ctx, client, targetURL, method, headerFormat, v)
		report.Results = append(report.Results, res)
		if res.Verdict == "SECURE" {
			report.Passed++
		} else if res.Verdict == "VULNERABLE" {
			report.Failed++
		} else {
			report.Errors++
		}
	}

	if report.TotalTests > 0 {
		report.ScorePct = float64(report.Passed) / float64(report.TotalTests) * 100.0
	}

	return report
}

func testSingleVector(ctx context.Context, client *http.Client, targetURL, method, headerFormat string, v AttackVector) TestResult {
	start := time.Now()

	req, err := http.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		return TestResult{
			VectorID:     v.ID,
			VectorName:   v.Name,
			Category:     v.Category,
			Severity:     v.Severity,
			Passed:       false,
			Verdict:      "ERROR",
			ErrorMessage: fmt.Sprintf("invalid request: %v", err),
			DurationMs:   time.Since(start).Milliseconds(),
		}
	}

	// Apply headers from format template
	lines := strings.Split(headerFormat, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.ReplaceAll(val, "{{token}}", v.Token)
			req.Header.Set(k, val)
		}
	}

	resp, err := client.Do(req)
	duration := time.Since(start).Milliseconds()

	if err != nil {
		return TestResult{
			VectorID:     v.ID,
			VectorName:   v.Name,
			Category:     v.Category,
			Severity:     v.Severity,
			Passed:       false,
			Verdict:      "ERROR",
			ErrorMessage: fmt.Sprintf("network error: %v", err),
			DurationMs:   duration,
		}
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	snippet := string(bodyBytes)

	// An authentication middleware is considered SECURE if it rejects with 401 Unauthorized or 403 Forbidden
	isSecure := resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
	isVulnerable := resp.StatusCode >= 200 && resp.StatusCode < 300

	verdict := "SECURE"
	if isVulnerable {
		verdict = "VULNERABLE"
	} else if !isSecure {
		verdict = fmt.Sprintf("STATUS_%d", resp.StatusCode)
	}

	return TestResult{
		VectorID:   v.ID,
		VectorName: v.Name,
		Category:   v.Category,
		Severity:   v.Severity,
		StatusCode: resp.StatusCode,
		StatusText: http.StatusText(resp.StatusCode),
		Passed:     isSecure,
		Verdict:    verdict,
		DurationMs: duration,
		Snippet:    snippet,
	}
}
