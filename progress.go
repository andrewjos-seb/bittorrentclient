package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// A live terminal dashboard. It redraws a fixed block of lines in place so the
// user sees throughput, ETA, worker count and piece progress moving in real
// time instead of scrolling log noise.
//
// When stdout is not a terminal (piped, redirected, running under CI) the
// in-place redraw would be garbage, so the dashboard degrades to one compact
// line every few seconds.

type progress_snapshot struct {
	name           string
	total_bytes    int64
	done_bytes     int64
	pieces_done    int
	pieces_total   int
	down_rate      float64
	up_rate        float64
	eta            time.Duration
	active_workers int
	connected      int
	unchoked       int
	uploaded       int64
	ratio          float64
	resumed        int
	elapsed        time.Duration
}

type dashboard struct {
	out       io.Writer
	enabled   bool
	tty       bool
	lines     int
	history   []float64
	last_line time.Time
	peak      float64
}

func new_dashboard(out io.Writer, enabled bool) *dashboard {
	db := &dashboard{out: out, enabled: enabled}
	if f, ok := out.(*os.File); ok {
		if info, err := f.Stat(); err == nil {
			db.tty = info.Mode()&os.ModeCharDevice != 0
		}
	}
	if os.Getenv("TERM") == "dumb" {
		db.tty = false
	}
	return db
}

func human_bytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	value := float64(n)
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	for _, u := range units {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.2f %s", value, u)
		}
	}
	return fmt.Sprintf("%.2f PiB", value/unit)
}

func human_rate(bytes_per_second float64) string {
	if bytes_per_second <= 0 {
		return "0 B/s"
	}
	return human_bytes(int64(bytes_per_second)) + "/s"
}

func human_duration(d time.Duration) string {
	if d <= 0 {
		return "--:--"
	}
	seconds := int64(d.Seconds())
	hours := seconds / 3600
	minutes := (seconds % 3600) / 60
	secs := seconds % 60
	if hours > 0 {
		return fmt.Sprintf("%d:%02d:%02d", hours, minutes, secs)
	}
	return fmt.Sprintf("%02d:%02d", minutes, secs)
}

func progress_bar(fraction float64, width int) string {
	if fraction < 0 {
		fraction = 0
	}
	if fraction > 1 {
		fraction = 1
	}
	filled := int(fraction*float64(width) + 0.5)
	return strings.Repeat("=", filled) + strings.Repeat("-", width-filled)
}

var spark_blocks = []rune("▁▂▃▄▅▆▇█")

func sparkline(values []float64, width int) string {
	if len(values) == 0 {
		return ""
	}
	if len(values) > width {
		values = values[len(values)-width:]
	}
	peak := 0.0
	for _, v := range values {
		if v > peak {
			peak = v
		}
	}
	if peak <= 0 {
		return strings.Repeat("▁", len(values))
	}

	var sb strings.Builder
	for _, v := range values {
		index := int(v / peak * float64(len(spark_blocks)-1))
		if index < 0 {
			index = 0
		}
		if index >= len(spark_blocks) {
			index = len(spark_blocks) - 1
		}
		sb.WriteRune(spark_blocks[index])
	}
	return sb.String()
}

func (db *dashboard) lines_for(s progress_snapshot) []string {
	fraction := 0.0
	if s.total_bytes > 0 {
		fraction = float64(s.done_bytes) / float64(s.total_bytes)
	}

	if s.down_rate > db.peak {
		db.peak = s.down_rate
	}
	db.history = append(db.history, s.down_rate)

	out := []string{
		fmt.Sprintf("  %s", s.name),
		fmt.Sprintf("  [%s] %6.2f%%   %s / %s", progress_bar(fraction, 30), fraction*100,
			human_bytes(s.done_bytes), human_bytes(s.total_bytes)),
		fmt.Sprintf("  down %-12s (peak %-12s)  up %-12s  ETA %s",
			human_rate(s.down_rate), human_rate(db.peak), human_rate(s.up_rate), human_duration(s.eta)),
		fmt.Sprintf("  pieces %d/%d   workers %d   peers %d (unchoked %d)   ratio %.2f   elapsed %s",
			s.pieces_done, s.pieces_total, s.active_workers, s.connected, s.unchoked, s.ratio,
			human_duration(s.elapsed)),
		fmt.Sprintf("  throughput %s", sparkline(db.history, 46)),
	}
	if s.resumed > 0 {
		out = append(out, fmt.Sprintf("  resumed %d verified piece(s) from the earlier run", s.resumed))
	}
	return out
}

func (db *dashboard) render(s progress_snapshot) {
	if !db.enabled {
		return
	}

	lines := db.lines_for(s)

	if !db.tty {
		// Non-interactive: a bounded line every few seconds, no cursor games.
		if time.Since(db.last_line) < 3*time.Second && s.done_bytes < s.total_bytes {
			return
		}
		db.last_line = time.Now()
		fmt.Fprintf(db.out, "%s %s/%s (%.2f%%) %s ETA %s\n",
			s.name, human_bytes(s.done_bytes), human_bytes(s.total_bytes),
			fraction_of(s), human_rate(s.down_rate), human_duration(s.eta))
		return
	}

	if db.lines > 0 {
		fmt.Fprintf(db.out, "\033[%dA", db.lines)
	}
	for _, line := range lines {
		fmt.Fprintf(db.out, "\033[2K%s\n", line)
	}
	db.lines = len(lines)
}

func fraction_of(s progress_snapshot) float64 {
	if s.total_bytes <= 0 {
		return 100
	}
	return float64(s.done_bytes) / float64(s.total_bytes) * 100
}

func (db *dashboard) finish(s progress_snapshot) {
	if !db.enabled {
		return
	}
	if !db.tty {
		fmt.Fprintf(db.out, "complete: %s (%s) downloaded, %s uploaded in %s\n",
			s.name, human_bytes(s.done_bytes), human_bytes(s.uploaded), human_duration(s.elapsed))
		return
	}

	lines := db.lines_for(s)
	if db.lines > 0 {
		fmt.Fprintf(db.out, "\033[%dA", db.lines)
	}
	for _, line := range lines {
		fmt.Fprintf(db.out, "\033[2K%s\n", line)
	}
	fmt.Fprintf(db.out, "  downloaded %s and uploaded %s in %s (ratio %.2f)\n",
		human_bytes(s.done_bytes), human_bytes(s.uploaded), human_duration(s.elapsed), s.ratio)
	db.lines = 0
}
