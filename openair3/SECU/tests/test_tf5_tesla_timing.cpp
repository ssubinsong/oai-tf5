/**
 * @file test_tf5_tesla_timing.cpp
 * @brief Unit tests for TF5 TESLA timing and replay protection functions
 *
 * Tests for:
 * - tf5_rp_get_wallclock_ms(): Wall-clock time retrieval
 * - tf5_rp_validate_timestamp(): Timestamp validation for replay protection (seconds)
 * - Helper functions: tf5_slot_time_make(), tf5_tesla_absolute_slots(), etc.
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
    static constexpr uint16_t T_INT_MS = 160;  // 160ms interval (= SIB1 broadcast period)

    void SetUp() override {
        // No setup needed
    }
};

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
// Timestamp Validation Tests (tf5_rp_validate_timestamp) — seconds
// ============================================================================

TEST_F(TF5TimingTest, ValidateTimestamp_WithinWindow_Valid) {
    uint64_t ue_time_s = 1000;  // Some reference time (seconds)
    uint32_t ext_timestamp_s = 1000 & 0xFFFFFFu;
    uint64_t window_s = 10800;  // 3 hour window

    int result = tf5_rp_validate_timestamp(ue_time_s, ext_timestamp_s, window_s);

    EXPECT_EQ(0, result) << "Exact same time should be valid";
}

TEST_F(TF5TimingTest, ValidateTimestamp_SlightlyOld_Valid) {
    uint64_t ue_time_s = 100000;
    uint32_t ext_timestamp_s = (100000 - 30) & 0xFFFFFFu;  // 30 seconds old
    uint64_t window_s = 10800;

    int result = tf5_rp_validate_timestamp(ue_time_s, ext_timestamp_s, window_s);

    EXPECT_EQ(0, result) << "30 seconds old within 3-hour window should be valid";
}

TEST_F(TF5TimingTest, ValidateTimestamp_SlightlyFuture_Valid) {
    uint64_t ue_time_s = 100000;
    uint32_t ext_timestamp_s = (100000 + 30) & 0xFFFFFFu;  // 30 seconds in future
    uint64_t window_s = 10800;

    int result = tf5_rp_validate_timestamp(ue_time_s, ext_timestamp_s, window_s);

    EXPECT_EQ(0, result) << "30 seconds in future within 3-hour window should be valid";
}

TEST_F(TF5TimingTest, ValidateTimestamp_TooOld) {
    uint64_t ue_time_s = 100000;
    uint32_t ext_timestamp_s = (100000 - 11000) & 0xFFFFFFu;  // 11000 seconds old
    uint64_t window_s = 10800;

    int result = tf5_rp_validate_timestamp(ue_time_s, ext_timestamp_s, window_s);

    EXPECT_EQ(TF5_ERR_TIMESTAMP_OLD, result) << "11000 seconds old should be rejected as too old";
}

TEST_F(TF5TimingTest, ValidateTimestamp_TooFuture) {
    uint64_t ue_time_s = 100000;
    uint32_t ext_timestamp_s = (100000 + 11000) & 0xFFFFFFu;  // 11000 seconds in future
    uint64_t window_s = 10800;

    int result = tf5_rp_validate_timestamp(ue_time_s, ext_timestamp_s, window_s);

    EXPECT_EQ(TF5_ERR_TIMESTAMP_FUTURE, result) << "11000 seconds in future should be rejected";
}

TEST_F(TF5TimingTest, ValidateTimestamp_ExactBoundaryOld_Valid) {
    uint64_t ue_time_s = 100000;
    uint32_t ext_timestamp_s = (100000 - 10800) & 0xFFFFFFu;  // Exactly at window edge
    uint64_t window_s = 10800;

    int result = tf5_rp_validate_timestamp(ue_time_s, ext_timestamp_s, window_s);

    EXPECT_EQ(0, result) << "Exactly at old boundary should be valid";
}

TEST_F(TF5TimingTest, ValidateTimestamp_ExactBoundaryFuture_Valid) {
    uint64_t ue_time_s = 100000;
    uint32_t ext_timestamp_s = (100000 + 10800) & 0xFFFFFFu;  // Exactly at window edge
    uint64_t window_s = 10800;

    int result = tf5_rp_validate_timestamp(ue_time_s, ext_timestamp_s, window_s);

    EXPECT_EQ(0, result) << "Exactly at future boundary should be valid";
}

TEST_F(TF5TimingTest, ValidateTimestamp_24BitWrap_PositiveWrap) {
    // Test 24-bit wraparound: UE at 0x100, ext at 0xFFFFF0
    // In 24-bit modular signed math: diff = 0x100 - 0xFFFFF0 = +0x110 (272 seconds old)
    uint64_t ue_time_s = 0x100;
    uint32_t ext_timestamp_s = 0xFFFFF0;
    uint64_t window_s = 10800;

    int result = tf5_rp_validate_timestamp(ue_time_s, ext_timestamp_s, window_s);

    EXPECT_EQ(0, result) << "24-bit wrap: ext 272s old should be valid";
}

TEST_F(TF5TimingTest, ValidateTimestamp_24BitWrap_NegativeWrap) {
    // UE near max (0xFFFFF0), ext just after wrap (0x100)
    // In 24-bit modular signed math: diff = 0xFFFFF0 - 0x100 = -0x110 (-272s, ext is in future)
    uint64_t ue_time_s = 0xFFFFF0;
    uint32_t ext_timestamp_s = 0x100;
    uint64_t window_s = 10800;

    int result = tf5_rp_validate_timestamp(ue_time_s, ext_timestamp_s, window_s);

    EXPECT_EQ(0, result) << "24-bit wrap: ext 272s in future should be valid";
}

TEST_F(TF5TimingTest, ValidateTimestamp_TimestampZero) {
    // Verify behavior when ext_timestamp_s = 0
    uint64_t ue_time_s = 500;
    uint32_t ext_timestamp_s = 0;
    uint64_t window_s = 10800;

    int result = tf5_rp_validate_timestamp(ue_time_s, ext_timestamp_s, window_s);

    EXPECT_EQ(0, result) << "ext_timestamp=0 with UE at 500s should be valid (500s old, within 3h window)";
}

TEST_F(TF5TimingTest, ValidateTimestamp_SmallWindow) {
    uint64_t ue_time_s = 100000;
    uint32_t ext_timestamp_s = (100000 - 50) & 0xFFFFFFu;  // 50 seconds old
    uint64_t window_s = 30;  // 30 second window

    int result = tf5_rp_validate_timestamp(ue_time_s, ext_timestamp_s, window_s);

    EXPECT_EQ(TF5_ERR_TIMESTAMP_OLD, result) << "50 seconds old should be rejected with 30 second window";
}

TEST_F(TF5TimingTest, ValidateTimestamp_JustOutsideWindow_TooOld) {
    uint64_t ue_time_s = 100000;
    uint32_t ext_timestamp_s = (100000 - 10801) & 0xFFFFFFu;  // 10801 seconds old
    uint64_t window_s = 10800;

    int result = tf5_rp_validate_timestamp(ue_time_s, ext_timestamp_s, window_s);

    EXPECT_EQ(TF5_ERR_TIMESTAMP_OLD, result) << "Timestamp just outside window (old) should be rejected";
}

TEST_F(TF5TimingTest, ValidateTimestamp_JustOutsideWindow_TooFuture) {
    uint64_t ue_time_s = 100000;
    uint32_t ext_timestamp_s = (100000 + 10801) & 0xFFFFFFu;  // 10801 seconds in future
    uint64_t window_s = 10800;

    int result = tf5_rp_validate_timestamp(ue_time_s, ext_timestamp_s, window_s);

    EXPECT_EQ(TF5_ERR_TIMESTAMP_FUTURE, result) << "Timestamp just outside window (future) should be rejected";
}

TEST_F(TF5TimingTest, ValidateTimestamp_LargeTimeDrift_Rejected) {
    uint64_t ue_time_s = 500000;
    uint32_t ext_timestamp_s = (500000 - 50000) & 0xFFFFFFu;  // ~14 hours old
    uint64_t window_s = 10800;  // 3 hour window

    int result = tf5_rp_validate_timestamp(ue_time_s, ext_timestamp_s, window_s);

    EXPECT_EQ(TF5_ERR_TIMESTAMP_OLD, result) << "Large time drift (~14 hours old) should be rejected with 3h window";
}

TEST_F(TF5TimingTest, ValidateTimestamp_ReplayAttackScenario) {
    // Scenario: Attacker records a valid SIB1 and tries to replay it later
    uint64_t original_time_s = 100000;
    uint32_t original_timestamp = original_time_s & 0xFFFFFFu;

    // UE validates immediately - should succeed
    int result1 = tf5_rp_validate_timestamp(original_time_s, original_timestamp, 10800);
    EXPECT_EQ(0, result1) << "Original timestamp should be valid";

    // Attacker waits 4 hours and replays
    uint64_t replay_time_s = original_time_s + 14400;  // 4 hours later
    int result2 = tf5_rp_validate_timestamp(replay_time_s, original_timestamp, 10800);
    EXPECT_EQ(TF5_ERR_TIMESTAMP_OLD, result2) << "Replayed timestamp (4 hours later) should be rejected";
}

TEST_F(TF5TimingTest, ValidateTimestamp_ZeroWindow) {
    uint64_t ue_time_s = 100000;
    uint32_t ext_timestamp_s = 100000 & 0xFFFFFFu;  // Same time
    uint64_t window_s = 0;

    int result = tf5_rp_validate_timestamp(ue_time_s, ext_timestamp_s, window_s);

    EXPECT_EQ(0, result) << "Exact same time with zero window should be valid";
}

// ============================================================================
// Helper Function Tests (inline functions in header)
// ============================================================================

TEST_F(TF5TimingTest, SlotTimeMake_Basic) {
    tf5_slot_time_t time = tf5_slot_time_make(500, 15);

    EXPECT_EQ(500, time.sfn);
    EXPECT_EQ(15, time.slot);
}

TEST_F(TF5TimingTest, AbsoluteSlots_Basic) {
    tf5_slot_time_t time = tf5_slot_time_make(10, 5);

    uint64_t abs_slots = tf5_absolute_slots(&time, SLOTS_PER_FRAME);

    EXPECT_EQ(10 * SLOTS_PER_FRAME + 5, abs_slots);
}

TEST_F(TF5TimingTest, SlotsToSlotTime_RoundTrip) {
    tf5_slot_time_t original = tf5_slot_time_make(123, 17);
    uint64_t abs_slots = tf5_absolute_slots(&original, SLOTS_PER_FRAME);
    tf5_slot_time_t recovered = tf5_slots_to_slot_time(abs_slots, SLOTS_PER_FRAME);

    EXPECT_EQ(original.sfn, recovered.sfn);
    EXPECT_EQ(original.slot, recovered.slot);
}

TEST_F(TF5TimingTest, SlotsToSlotTime_SfnWrap) {
    // Test SFN modulo 1024
    uint64_t abs_slots = 1024 * SLOTS_PER_FRAME + 5;  // SFN would be 1024, wraps to 0
    tf5_slot_time_t time = tf5_slots_to_slot_time(abs_slots, SLOTS_PER_FRAME);

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
