//! Automated benchmarks and integration tests for M0.5a Rust-UI Spike.

use std::time::Instant;
use ui_rust_spike::atlas::GlyphAtlasStub;
use ui_rust_spike::harness::{AppHarness, SelectionRange};
use ui_rust_spike::memory_model::MemoryCalculator;
use ui_rust_spike::viewport::TerminalViewport;

/// Test 1: 100,000-line `cat hugefile` burst processing.
/// Verifies dirty-row batching keeps per-frame render work well below the 16 ms (60 FPS) budget.
#[test]
fn test_100k_lines_cat_hugefile_burst_under_16ms_budget() {
    const TOTAL_LINES: usize = 100_000;
    const LINES_PER_FRAME_BURST: usize = 250; // Lines received per 16.6 ms render tick
    const COLS: usize = 120;
    const ROWS: usize = 40;
    const SCROLLBACK: usize = 10_000;

    let mut viewport = TerminalViewport::new(COLS, ROWS, SCROLLBACK);
    let mut atlas = GlyphAtlasStub::new(2048, 2048);

    let sample_line =
        "2026-11-06T15:00:00.123Z [INFO] systemd[1]: Started EasySSH Core Daemon Worker #42.";

    let start_time = Instant::now();
    let mut frame_durations = Vec::with_capacity(TOTAL_LINES / LINES_PER_FRAME_BURST + 1);
    let mut total_frames = 0;
    let mut total_render_micros = 0u128;
    let mut lines_processed = 0;

    while lines_processed < TOTAL_LINES {
        let chunk_size = LINES_PER_FRAME_BURST.min(TOTAL_LINES - lines_processed);

        // Feed chunk into viewport (scrolls when bottom row is reached)
        for i in 0..chunk_size {
            let row = (lines_processed + i) % ROWS;
            viewport.write_str(row, 0, sample_line);
            if row == ROWS - 1 {
                viewport.scroll_up(1);
            }
        }
        lines_processed += chunk_size;

        // Simulate frame render at display vsync
        let frame_start = Instant::now();
        let metrics = viewport.render_frame_simulated(&mut atlas, 2.0);
        let frame_micros = frame_start.elapsed().as_micros();

        frame_durations.push(frame_micros);
        total_render_micros += frame_micros;
        total_frames += 1;

        assert!(
            metrics.dirty_rows_count <= ROWS,
            "Dirty rows should not exceed total rows"
        );
    }

    let elapsed_total = start_time.elapsed();
    frame_durations.sort_unstable();

    let avg_frame_micros = total_render_micros as f64 / total_frames as f64;
    let avg_frame_ms = avg_frame_micros / 1000.0;
    let p95_idx = ((total_frames as f64) * 0.95).floor() as usize;
    let p95_frame_ms = frame_durations[p95_idx.min(total_frames - 1)] as f64 / 1000.0;
    let p99_idx = ((total_frames as f64) * 0.99).floor() as usize;
    let p99_frame_ms = frame_durations[p99_idx.min(total_frames - 1)] as f64 / 1000.0;
    let max_frame_ms = frame_durations.last().copied().unwrap_or(0) as f64 / 1000.0;

    println!("=== 100,000-Line Burst Benchmark Results ===");
    println!("Total Lines Processed : {}", TOTAL_LINES);
    println!("Total Frames Simulated: {}", total_frames);
    println!("Total Wall Clock Time : {:.2?}", elapsed_total);
    println!("Average Frame Render  : {:.3} ms", avg_frame_ms);
    println!("P95 Frame Render Time : {:.3} ms", p95_frame_ms);
    println!("P99 Frame Render Time : {:.3} ms", p99_frame_ms);
    println!("Max Frame Render Time : {:.3} ms", max_frame_ms);
    println!("Glyph Atlas Hit Ratio : {:.2}%", atlas.hit_ratio() * 100.0);
    println!("Unique Cached Glyphs  : {}", atlas.entry_count());

    // Critical assertion: Average and P95 frame render times MUST be well within the 16.6 ms budget!
    assert!(
        avg_frame_ms < 5.0,
        "Average frame render ({:.3} ms) exceeded 5 ms threshold",
        avg_frame_ms
    );
    assert!(
        p95_frame_ms < 16.0,
        "P95 frame render ({:.3} ms) exceeded 16 ms budget!",
        p95_frame_ms
    );
}

/// Test 2: Memory footprint calculation confirming < 80 MB idle/active session RAM target.
#[test]
fn test_memory_footprint_verification_under_80mb() {
    // Idle Session (fresh window, 1 session, 500 lines scrollback, 1024x1024 atlas, 50 hosts)
    let idle = MemoryCalculator::calculate(80, 24, 500, 1024, 50);
    let idle_mb = idle.total_mib();

    println!("Idle Session RAM Footprint: {:.2} MiB", idle_mb);
    assert!(
        idle_mb < 30.0,
        "Idle RAM ({:.2} MiB) must be under 30 MiB",
        idle_mb
    );

    // Active Heavy Session (160 cols, 60 rows, 10,000 lines scrollback, 2048x2048 atlas, 500 hosts)
    let active = MemoryCalculator::calculate(160, 60, 10000, 2048, 500);
    let active_mb = active.total_mib();

    println!("Active Session RAM Footprint: {:.2} MiB", active_mb);
    println!(
        "  - Visible Grid RAM : {:.2} KiB",
        active.terminal_visible_grid_bytes as f64 / 1024.0
    );
    println!(
        "  - Scrollback RAM   : {:.2} MiB",
        active.scrollback_history_bytes as f64 / (1024.0 * 1024.0)
    );
    println!(
        "  - Glyph Atlas RAM  : {:.2} MiB",
        active.glyph_atlas_texture_bytes as f64 / (1024.0 * 1024.0)
    );
    println!(
        "  - wgpu Buffers RAM : {:.2} MiB",
        active.wgpu_buffers_bytes as f64 / (1024.0 * 1024.0)
    );
    println!(
        "  - UI Runtime Base  : {:.2} MiB",
        active.ui_framework_runtime_baseline_bytes as f64 / (1024.0 * 1024.0)
    );

    // Strict compliance with AGENT.md Section 6 (< 80 MB)
    assert!(
        active_mb < 80.0,
        "Active session RAM ({:.2} MiB) must strictly not exceed 80 MB target",
        active_mb
    );
}

/// Test 3: HiDPI glyph scaling, IME preedit overlay positioning, and mouse text selection.
#[test]
fn test_hidpi_ime_and_mouse_selection() {
    // 1. HiDPI Glyph Scaling
    let (w1, h1) = GlyphAtlasStub::scaled_cell_size(8.0, 16.0, 1.0);
    assert_eq!((w1, h1), (8.0, 16.0));

    let (w15, h15) = GlyphAtlasStub::scaled_cell_size(8.0, 16.0, 1.5);
    assert_eq!((w15, h15), (12.0, 24.0));

    let (w2, h2) = GlyphAtlasStub::scaled_cell_size(8.0, 16.0, 2.0);
    assert_eq!((w2, h2), (16.0, 32.0));

    // 2. IME Preedit Overlay Positioning & Clamping
    let mut harness = AppHarness::new(100, 30);
    harness.active_tab.viewport.cursor_col = 25;
    harness.active_tab.viewport.cursor_row = 10;

    // Normal positioning within bounds
    let ime_pos = harness.calculate_ime_popup_position(
        harness.active_tab.viewport.cursor_col,
        harness.active_tab.viewport.cursor_row,
        8.0,
        16.0,
        1.5,
        1920.0,
        1080.0,
    );
    // Origin X = 260 * 1.5 = 390. Cell W = 12. Cursor col 25 -> 390 + 25 * 12 = 690
    assert_eq!(ime_pos.x_px, 690.0);
    // Origin Y = 36 * 1.5 = 54. Cell H = 24. (10 + 1) * 24 = 264 -> 54 + 264 = 318
    assert_eq!(ime_pos.y_px, 318.0);

    // Boundary clamping at bottom-right corner of screen
    let clamped_pos = harness.calculate_ime_popup_position(99, 29, 8.0, 16.0, 1.0, 800.0, 600.0);
    assert!(
        clamped_pos.x_px <= 600.0,
        "IME popup X must be clamped to prevent window overflow"
    );
    assert!(
        clamped_pos.y_px <= 500.0,
        "IME popup Y must be clamped to prevent window overflow"
    );

    // 3. Mouse Selection and Copy Extraction
    harness
        .active_tab
        .viewport
        .write_str(0, 0, "curl -sSL https://get.easyssh.dev | sh");
    harness
        .active_tab
        .viewport
        .write_str(1, 0, "EasySSH installed successfully!");

    // Hit-test mouse coordinates to cell
    let cell_coord = harness
        .hit_test_pixel_to_cell(260.0 + 8.0 * 5.0, 36.0 + 16.0 * 0.5, 8.0, 16.0, 1.0)
        .expect("Pixel should hit terminal grid");
    assert_eq!(cell_coord, (5, 0));

    // Multi-line selection extraction
    let sel = SelectionRange {
        start_col: 0,
        start_row: 0,
        end_col: 6,
        end_row: 1,
    };
    let copied_text = harness.extract_selected_text(&sel);
    assert_eq!(
        copied_text,
        "curl -sSL https://get.easyssh.dev | sh\nEasySSH"
    );
}
