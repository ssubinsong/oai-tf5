/**
 * @file test_tf5_tesla_timing.cpp
 * @brief Unit tests for TF5 TESLA timing and replay protection functions
 *
 * Tests for:
 * - tf5_tesla_slots_since_t0(): Slot time calculation
 * - tf5_tesla_get_interval_index(): Interval index calculation
 * - tf5_rp_get_wallclock_ms(): Wall-clock time retrieval
 * - tf5_rp_validate_timestamp(): Timestamp validation for replay protection
 */

#include <gtest/gtest.h>
#include <cstring>
#include <thread>
#include <chrono>

extern "C" {
#include "openair3/SECU/tf5_tesla.h"
}

class TF5TimingTest : public ::testing::Test {
protected:
    // Standard NR FR1 numerology 1: 2 slots per subframe = 20 slots per frame
    static constexpr uint16_t SLOTS_PER_FRAME = 20;
    static constexpr uint16_t T_INT_MS = 20;  // 20ms interval

    void SetUp() override {
        // No setup needed
    }
};

// ============================================================================
// Slots Since T0 Tests (tf5_tesla_slots_since_t0)
// ============================================================================

TEST_F(TF5TimingTest, SlotsSinceT0_AtT0_ReturnsZero) {
    tf5_tesla_slot_time_t t0 = tf5_slot_time_make(100, 5);
    tf5_tesla_slot_time_t current = t0;

    uint64_t slots = tf5_tesla_slots_since_t0(&current, &t0, SLOTS_PER_FRAME);

    EXPECT_EQ(0u, slots) << "At T_0, slots since T_0 should be 0";
}

TEST_F(TF5TimingTest, SlotsSinceT0_AfterOneSlot) {
    tf5_tesla_slot_time_t t0 = tf5_slot_time_make(100, 5);
    tf5_tesla_slot_time_t current = tf5_slot_time_make(100, 6);

    uint64_t slots = tf5_tesla_slots_since_t0(&current, &t0, SLOTS_PER_FRAME);

    EXPECT_EQ(1u, slots) << "One slot after T_0 should return 1";
}

TEST_F(TF5TimingTest, SlotsSinceT0_AfterOneFrame) {
    tf5_tesla_slot_time_t t0 = tf5_slot_time_make(100, 0);
    tf5_tesla_slot_time_t current = tf5_slot_time_make(101, 0);

    uint64_t slots = tf5_tesla_slots_since_t0(&current, &t0, SLOTS_PER_FRAME);

    EXPECT_EQ(SLOTS_PER_FRAME, slots) << "One frame after T_0 should return slots_per_frame";
}

TEST_F(TF5TimingTest, SlotsSinceT0_SlotWrap) {
    // T_0 at SFN 100, slot 19 (last slot of frame)
    // Current at SFN 101, slot 0 (first slot of next frame)
    tf5_tesla_slot_time_t t0 = tf5_slot_time_make(100, SLOTS_PER_FRAME - 1);
    tf5_tesla_slot_time_t current = tf5_slot_time_make(101, 0);

    uint64_t slots = tf5_tesla_slots_since_t0(&current, &t0, SLOTS_PER_FRAME);

    EXPECT_EQ(1u, slots) << "Slot wraparound should be handled correctly";
}

TEST_F(TF5TimingTest, SlotsSinceT0_BeforeT0_ReturnsZero) {
    tf5_tesla_slot_time_t t0 = tf5_slot_time_make(100, 5);
    tf5_tesla_slot_time_t current = tf5_slot_time_make(100, 3);

    uint64_t slots = tf5_tesla_slots_since_t0(&current, &t0, SLOTS_PER_FRAME);

    EXPECT_EQ(0u, slots) << "Before T_0 should return 0 (clamped)";
}

TEST_F(TF5TimingTest, SlotsSinceT0_LargeGap) {
    tf5_tesla_slot_time_t t0 = tf5_slot_time_make(0, 0);
    tf5_tesla_slot_time_t current = tf5_slot_time_make(512, 10);

    uint64_t slots = tf5_tesla_slots_since_t0(&current, &t0, SLOTS_PER_FRAME);
    uint64_t expected = 512 * SLOTS_PER_FRAME + 10;

    EXPECT_EQ(expected, slots) << "Large time gap should be calculated correctly";
}

// ============================================================================
// Get Interval Index Tests (tf5_tesla_get_interval_index)
// ============================================================================

TEST_F(TF5TimingTest, GetIntervalIndex_AtT0_ReturnsZero) {
    tf5_tesla_slot_time_t t0 = tf5_slot_time_make(100, 0);
    tf5_tesla_slot_time_t current = t0;

    uint32_t interval = tf5_tesla_get_interval_index(&current, &t0, T_INT_MS, SLOTS_PER_FRAME);

    EXPECT_EQ(0u, interval) << "At T_0, interval should be 0";
}

TEST_F(TF5TimingTest, GetIntervalIndex_AfterOneInterval) {
    // T_int = 20ms, one frame = 10ms, so 2 frames = 1 interval
    tf5_tesla_slot_time_t t0 = tf5_slot_time_make(100, 0);
    tf5_tesla_slot_time_t current = tf5_slot_time_make(102, 0);  // 2 frames = 20ms

    uint32_t interval = tf5_tesla_get_interval_index(&current, &t0, T_INT_MS, SLOTS_PER_FRAME);

    EXPECT_EQ(1u, interval) << "After one T_int (20ms), interval should be 1";
}

TEST_F(TF5TimingTest, GetIntervalIndex_PartialInterval_Floor) {
    // T_int = 20ms = 2 frames. At 1.5 frames (15ms), should still be interval 0
    tf5_tesla_slot_time_t t0 = tf5_slot_time_make(100, 0);
    // 1 frame + 10 slots = 30 slots = 15ms
    tf5_tesla_slot_time_t current = tf5_slot_time_make(101, 10);

    uint32_t interval = tf5_tesla_get_interval_index(&current, &t0, T_INT_MS, SLOTS_PER_FRAME);

    EXPECT_EQ(0u, interval) << "Partial interval should floor to 0";
}

TEST_F(TF5TimingTest, GetIntervalIndex_ExactBoundary) {
    // At exactly 40ms = interval 2
    tf5_tesla_slot_time_t t0 = tf5_slot_time_make(100, 0);
    tf5_tesla_slot_time_t current = tf5_slot_time_make(104, 0);  // 4 frames = 40ms

    uint32_t interval = tf5_tesla_get_interval_index(&current, &t0, T_INT_MS, SLOTS_PER_FRAME);

    EXPECT_EQ(2u, interval) << "At exactly 40ms, interval should be 2";
}

TEST_F(TF5TimingTest, GetIntervalIndex_LargeValues) {
    // Test with many intervals
    tf5_tesla_slot_time_t t0 = tf5_slot_time_make(0, 0);
    // 1000 frames = 10 seconds = 500 intervals (at 20ms each)
    tf5_tesla_slot_time_t current = tf5_slot_time_make(1000, 0);

    uint32_t interval = tf5_tesla_get_interval_index(&current, &t0, T_INT_MS, SLOTS_PER_FRAME);

    EXPECT_EQ(500u, interval) << "10 seconds should give 500 intervals at 20ms each";
}

TEST_F(TF5TimingTest, GetIntervalIndex_DifferentTint) {
    // Test with different T_int (40ms)
    tf5_tesla_slot_time_t t0 = tf5_slot_time_make(0, 0);
    tf5_tesla_slot_time_t current = tf5_slot_time_make(8, 0);  // 8 frames = 80ms

    uint32_t interval = tf5_tesla_get_interval_index(&current, &t0, 40, SLOTS_PER_FRAME);

    EXPECT_EQ(2u, interval) << "80ms with T_int=40ms should give interval 2";
}

// ============================================================================
// Wall-clock Time Tests (tf5_rp_get_wallclock_ms)
// ============================================================================

TEST_F(TF5TimingTest, GetWallclockMs_ReturnsNonZero) {
    uint64_t time_ms = tf5_rp_get_wallclock_ms();

    EXPECT_GT(time_ms, 0u) << "Wall-clock time should be non-zero";
}

TEST_F(TF5TimingTest, GetWallclockMs_ReasonableValue) {
    // Should be after 2020-01-01 (1577836800000 ms)
    uint64_t time_ms = tf5_rp_get_wallclock_ms();
    uint64_t jan_2020_ms = 1577836800000ULL;

    EXPECT_GT(time_ms, jan_2020_ms) << "Wall-clock should be after January 2020";
}

TEST_F(TF5TimingTest, GetWallclockMs_Monotonic) {
    uint64_t time1 = tf5_rp_get_wallclock_ms();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    uint64_t time2 = tf5_rp_get_wallclock_ms();

    EXPECT_GE(time2, time1) << "Subsequent calls should return increasing values";
}

TEST_F(TF5TimingTest, GetWallclockMs_IncrementsCorrectly) {
    uint64_t time1 = tf5_rp_get_wallclock_ms();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    uint64_t time2 = tf5_rp_get_wallclock_ms();

    // Should have advanced by at least 90ms (allowing for timing variance)
    EXPECT_GE(time2 - time1, 90u) << "After 100ms sleep, time should advance by ~100ms";
}

// ============================================================================
// Timestamp Validation Tests (tf5_rp_validate_timestamp)
// ============================================================================

TEST_F(TF5TimingTest, ValidateTimestamp_WithinWindow_Valid) {
    uint64_t ue_time_ms = 1000000;  // Some reference time
    uint32_t ext_timestamp_ms = 1000000 & 0xFFFFFFu;  // Same time (24-bit)
    uint64_t window_ms = 60000;  // 60 second window

    int result = tf5_rp_validate_timestamp(ue_time_ms, ext_timestamp_ms, window_ms);

    EXPECT_EQ(0, result) << "Exact same time should be valid";
}

TEST_F(TF5TimingTest, ValidateTimestamp_SlightlyOld_Valid) {
    uint64_t ue_time_ms = 1000000;
    uint32_t ext_timestamp_ms = (1000000 - 30000) & 0xFFFFFFu;  // 30 seconds old
    uint64_t window_ms = 60000;

    int result = tf5_rp_validate_timestamp(ue_time_ms, ext_timestamp_ms, window_ms);

    EXPECT_EQ(0, result) << "30 seconds old within 60 second window should be valid";
}

TEST_F(TF5TimingTest, ValidateTimestamp_SlightlyFuture_Valid) {
    uint64_t ue_time_ms = 1000000;
    uint32_t ext_timestamp_ms = (1000000 + 30000) & 0xFFFFFFu;  // 30 seconds in future
    uint64_t window_ms = 60000;

    int result = tf5_rp_validate_timestamp(ue_time_ms, ext_timestamp_ms, window_ms);

    EXPECT_EQ(0, result) << "30 seconds in future within 60 second window should be valid";
}

TEST_F(TF5TimingTest, ValidateTimestamp_TooOld) {
    uint64_t ue_time_ms = 1000000;
    uint32_t ext_timestamp_ms = (1000000 - 70000) & 0xFFFFFFu;  // 70 seconds old
    uint64_t window_ms = 60000;

    int result = tf5_rp_validate_timestamp(ue_time_ms, ext_timestamp_ms, window_ms);

    EXPECT_EQ(-1, result) << "70 seconds old should be rejected as too old";
}

TEST_F(TF5TimingTest, ValidateTimestamp_TooFuture) {
    uint64_t ue_time_ms = 1000000;
    uint32_t ext_timestamp_ms = (1000000 + 70000) & 0xFFFFFFu;  // 70 seconds in future
    uint64_t window_ms = 60000;

    int result = tf5_rp_validate_timestamp(ue_time_ms, ext_timestamp_ms, window_ms);

    EXPECT_EQ(-2, result) << "70 seconds in future should be rejected";
}

TEST_F(TF5TimingTest, ValidateTimestamp_ExactBoundaryOld_Valid) {
    uint64_t ue_time_ms = 1000000;
    uint32_t ext_timestamp_ms = (1000000 - 60000) & 0xFFFFFFu;  // Exactly at window edge
    uint64_t window_ms = 60000;

    int result = tf5_rp_validate_timestamp(ue_time_ms, ext_timestamp_ms, window_ms);

    EXPECT_EQ(0, result) << "Exactly at old boundary should be valid";
}

TEST_F(TF5TimingTest, ValidateTimestamp_ExactBoundaryFuture_Valid) {
    uint64_t ue_time_ms = 1000000;
    uint32_t ext_timestamp_ms = (1000000 + 60000) & 0xFFFFFFu;  // Exactly at window edge
    uint64_t window_ms = 60000;

    int result = tf5_rp_validate_timestamp(ue_time_ms, ext_timestamp_ms, window_ms);

    EXPECT_EQ(0, result) << "Exactly at future boundary should be valid";
}

TEST_F(TF5TimingTest, ValidateTimestamp_24BitWrap_PositiveWrap) {
    // Test 24-bit wraparound: UE at 0x100, ext at 0xFFFFF0 (appears to be in future due to wrap)
    // This tests the LSB comparison logic
    uint64_t ue_time_ms = 0x100;  // UE has wrapped around
    uint32_t ext_timestamp_ms = 0xFFFFF0;  // gNB hasn't wrapped yet (appears future)
    uint64_t window_ms = 60000;

    // The 24-bit difference: 0x100 - 0xFFFFF0 = 0x100 - 0xFFFFF0 in 24-bit space
    // This is a large negative value in signed interpretation, which means ext is "in the future"
    // But since 0xFFFFF0 is close to wrap, ext is actually just slightly old
    // The function should handle this case

    int result = tf5_rp_validate_timestamp(ue_time_ms, ext_timestamp_ms, window_ms);

    // In 24-bit math: 0x100 - 0xFFFFF0 wraps to a small positive value (0x110)
    // So ext appears to be 0x110 ms old, which is within the window
    EXPECT_EQ(0, result) << "24-bit wrap case should handle correctly";
}

TEST_F(TF5TimingTest, ValidateTimestamp_SmallWindow) {
    uint64_t ue_time_ms = 1000000;
    uint32_t ext_timestamp_ms = (1000000 - 5000) & 0xFFFFFFu;  // 5 seconds old
    uint64_t window_ms = 3000;  // 3 second window

    int result = tf5_rp_validate_timestamp(ue_time_ms, ext_timestamp_ms, window_ms);

    EXPECT_EQ(-1, result) << "5 seconds old should be rejected with 3 second window";
}

TEST_F(TF5TimingTest, ValidateTimestamp_ZeroWindow) {
    uint64_t ue_time_ms = 1000000;
    uint32_t ext_timestamp_ms = 1000000 & 0xFFFFFFu;  // Same time
    uint64_t window_ms = 0;

    int result = tf5_rp_validate_timestamp(ue_time_ms, ext_timestamp_ms, window_ms);

    EXPECT_EQ(0, result) << "Exact same time with zero window should be valid";
}

// ============================================================================
// Helper Function Tests (inline functions in header)
// ============================================================================

TEST_F(TF5TimingTest, SlotTimeMake_Basic) {
    tf5_tesla_slot_time_t time = tf5_slot_time_make(500, 15);

    EXPECT_EQ(500, time.sfn);
    EXPECT_EQ(15, time.slot);
}

TEST_F(TF5TimingTest, AbsoluteSlots_Basic) {
    tf5_tesla_slot_time_t time = tf5_slot_time_make(10, 5);

    uint64_t abs_slots = tf5_tesla_absolute_slots(&time, SLOTS_PER_FRAME);

    EXPECT_EQ(10 * SLOTS_PER_FRAME + 5, abs_slots);
}

TEST_F(TF5TimingTest, SlotsToSlotTime_RoundTrip) {
    tf5_tesla_slot_time_t original = tf5_slot_time_make(123, 17);
    uint64_t abs_slots = tf5_slot_time_to_slots(&original, SLOTS_PER_FRAME);
    tf5_tesla_slot_time_t recovered = tf5_slots_to_slot_time(abs_slots, SLOTS_PER_FRAME);

    EXPECT_EQ(original.sfn, recovered.sfn);
    EXPECT_EQ(original.slot, recovered.slot);
}

TEST_F(TF5TimingTest, SlotsToSlotTime_SfnWrap) {
    // Test SFN modulo 1024
    uint64_t abs_slots = 1024 * SLOTS_PER_FRAME + 5;  // SFN would be 1024, wraps to 0
    tf5_tesla_slot_time_t time = tf5_slots_to_slot_time(abs_slots, SLOTS_PER_FRAME);

    EXPECT_EQ(0, time.sfn) << "SFN should wrap at 1024";
    EXPECT_EQ(5, time.slot);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
