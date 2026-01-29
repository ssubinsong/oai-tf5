# Time Synchronization for TF5 Bootstrapping

[Back to Index](index.md)

---

This document consolidates the time-synchronization model and the TESLA "safe packet" timing check for TF5.

## References

- **RFC 4082 Section 2.2**: Time synchronization requirements for TESLA
- **3GPP TS 38.101**: UE RF conformance requirements (timing accuracy bounds)
- **3GPP TS 38.133**: UE measurement requirements (synchronization accuracy)

---

## 1. Goal and Context

TESLA requires each receiver to be loosely time-synchronized with the sender in the following sense:

- The receiver must know an **upper bound** on how far its clock can lag behind the sender’s clock, denoted here as $D$ (analogous to TESLA’s $D_t$).

In bootstrapping, we assume **downlink-only** operation prior to authentication (no uplink handshake to compute $D$). Therefore, we rely on **PHY-layer radio-time alignment** (frame/slot timing) and **offline-provisioned bounds** to obtain a conservative $D$ usable in TESLA’s safe-packet test.

---

## 2. Notation

### 2.1 Real (ideal) time

- $\tau \in \mathbb{R}$: ideal “real time” (not directly observable).

### 2.2 Clocks (radio-time clocks)

- Sender (gNB) PHY/radio clock:
  $$C_s : \mathbb{R} \to \mathbb{R},\quad \tau \mapsto C_s(\tau)$$
- Receiver (UE) PHY/radio clock:
  $$C_r : \mathbb{R} \to \mathbb{R},\quad \tau \mapsto C_r(\tau)$$

These are not wall clocks. They represent the radio time axis (frame/slot/symbol timing) each side uses internally.

### 2.3 Same-time clock skew

Define the same-real-time skew:
$$\Delta(\tau) \triangleq C_s(\tau) - C_r(\tau)$$

TESLA’s safe-packet test assumes an upper bound:
$$\forall \tau,\quad \Delta(\tau) \le D$$

Equivalently:
$$C_s(\tau) \le C_r(\tau) + D \quad \text{for all } \tau.$$

### 2.4 Propagation delay (real-time)

For a particular transmission:

- gNB transmits at real time $\tau_{tx}$
- UE receives at real time $\tau_{rx}$

Propagation delay:
$$\tau_{\text{prop}} \triangleq \tau_{rx} - \tau_{tx} > 0$$

Assume an engineering bound:
$$0 \le \tau_{\text{prop}} \le \tau_{\text{prop,max}}.$$

Important: TESLA security does not require knowing $\tau_{\text{prop}}$ at runtime; propagation and processing primarily affect availability (how many packets remain verifiable), not the correctness of the safe-packet check when $D$ is conservative.

---

## 3. What “Synchronization” Means Here

### 3.1 Event-based alignment (tx–rx) and sync error $E_{\text{sync}}$

Consider a PHY synchronization “event”:

- Sender emits a sync reference at $\tau_{\text{sync,tx}}$
- Receiver observes it at $\tau_{\text{sync,rx}} = \tau_{\text{sync,tx}} + \tau_{\text{prop,sync}}$

Synchronization accuracy is captured as:
$$C_r(\tau_{\text{sync,rx}}) = C_s(\tau_{\text{sync,tx}}) + \epsilon_{\text{sync}},\quad |\epsilon_{\text{sync}}| \le E_{\text{sync}}.$$

Equivalently:
$$|C_r(\tau_{\text{sync,rx}}) - C_s(\tau_{\text{sync,tx}})| \le E_{\text{sync}}.$$

Key point: $E_{\text{sync}}$ bounds an error between two different real-time instants ($\tau_{\text{sync,tx}}$ vs. $\tau_{\text{sync,rx}}$). It is not, by definition, a same-$\tau$ skew bound.

### 3.2 From event-based alignment to same-time skew bounds

TESLA’s safe-packet test needs a bound on $\Delta(\tau)$ at the same real time $\tau$.
We obtain such a bound by combining:

1. The post-sync alignment error $E_{\text{sync}}$
2. Clock drift bounds (ppm) over a bounded time horizon
3. A conservative implementation margin

---

## 4. Drift Model and Bounding $D$

### 4.1 Drift bounds (ppm-style)

Model drift accumulation functions $f_s(\cdot)$ and $f_r(\cdot)$ such that:
$$C_s(\tau) = C_s(\tau_0) + f_s(\tau - \tau_0),$$
$$C_r(\tau) = C_r(\tau_1) + f_r(\tau - \tau_1).$$

Assume bounded drift rates:
$$|f_s(x)| \le E_s |x|,\quad |f_r(x)| \le E_r |x|,$$
where:

- $E_s$: sender (gNB) max drift rate (e.g., ppm converted to time-error per second)
- $E_r$: receiver (UE) max drift rate (worst-case conformance bound for “honest/compliant” UEs)

### 4.2 Operating horizon (re-sync cadence)

Let $\Delta T_{\max}$ be the maximum real-time duration for which we expect the PHY time alignment to remain valid without requiring a new synchronization “event” (or without assuming tighter tracking).

### 4.3 A conservative bound for same-time skew

Over the operating horizon, a standard conservative bound is:
$$D_{\text{theory}} \triangleq E_{\text{sync}} + (E_s + E_r)\Delta T_{\max}.$$

If you want to be extremely literal about the sync equation relating tx–rx instants, you may add a term of the form $E_s \tau_{\text{prop,max}}$ (prop-delay times ppm). This term is typically negligible compared to $E_{\text{sync}}$ and the drift term.

### 4.4 Implementation margin

Define the operational bound used by TESLA as:
$$D \triangleq D_{\text{theory}} + M_{\text{impl}}.$$

$M_{\text{impl}}$ absorbs:

- modeling conservatism in $E_{\text{sync}}$ (multipath, estimator corner cases),
- residual timestamping quantization/jitter,
- any extra safety slack (often easiest to choose in “symbols” or “slots” if implementing the test in radio-time units).

---

## 5. Mapping TESLA Time to PHY Time (Intervals)

TESLA divides time into uniform intervals of duration $T_{\text{int}}$, starting at sender-time origin $T_0$.

Sender-side interval index at real time $\tau$:
$$I_s(\tau) \triangleq \left\lfloor \frac{C_s(\tau) - T_0}{T_{\text{int}}} \right\rfloor.$$

A packet sent in interval $i$ uses key $K_i$, disclosed after delay $d$ intervals (i.e., disclosed in interval $i+d$).

---

## 6. Receiver “Safe Packet” Timing Test (TESLA Condition)

Upon receiving a packet $P_j$ carrying interval index $i$, the receiver:

1. Records arrival time immediately (as close to PHY arrival as feasible):
   $$T \triangleq C_r(\tau_{rx,j}).$$

2. Computes an upper bound on the sender’s clock at the moment of arrival:
   $$t_j \triangleq T + D.$$

3. Computes the highest sender interval the sender could be in:
   $$x \triangleq \left\lfloor \frac{t_j - T_0}{T_{\text{int}}} \right\rfloor.$$

4. Performs the safe packet test:
   $$x < i + d.$$

If true, then at arrival time the sender could not yet have reached the disclosure interval for key $K_i$, so the packet is safe to buffer (though not yet verifiable until disclosure).
If the test fails, the receiver treats the packet as unsafe/unverified (typically drop or do not buffer for later authentication).

---

## 7. What the Sender Must “Guarantee” (and How)

To instantiate this safely, the network (system designer / PLMN / gNB vendor) provisions bounds for:

1. $E_s$ (gNB drift bound)
   - Under sender control via oscillator/clock discipline and conformance testing.

2. $E_r$ (UE drift bound)
   - Not known per-device at runtime; taken as the worst-case UE conformance bound for “honest/compliant” UEs.

3. $E_{\text{sync}}$ (sync accuracy bound)
   - Derived from PHY sync/tracking design and validated empirically.
   - Practically: define it for the class of UEs that can successfully decode the relevant broadcast channel(s) under minimum service conditions.

4. $\Delta T_{\max}$ (validity horizon)
   - A design choice: shorter $\Delta T_{\max}$ reduces $D$.

5. $M_{\text{impl}}$ (margin)
   - Chosen to absorb implementation uncertainties; commonly easiest to pick as an integer multiple of a radio-time quantum (symbol/slot).

6. (Optional) $\tau_{\text{prop,max}}$
   - Used for ultra-conservative analysis; TESLA security itself does not require runtime knowledge of propagation delay.

---

## 8. Practical Interpretation (The “20 ms” Intuition)

When we say “UE is synchronized,” we do not mean the UE receives a signal at the same real time it was transmitted (impossible). Instead:

- If the gNB transmits something aligned to its radio-time at “20 ms,”
- the UE’s radio-time clock labels the received waveform as belonging to that “20 ms” point (up to $E_{\text{sync}}$),
- while the actual physical reception occurs later in real time by $\tau_{\text{prop}}$.

TESLA’s safety check uses the UE’s recorded arrival time in its radio-time clock plus the bound $D$ to ensure the key could not have been disclosed yet.

---

## 9. Implementation Checklist (Receiver Side)

**Provisioned/configured inputs:**

- $T_0, T_{\text{int}}, d$ (TESLA schedule)
- $D$ (clock-skew bound)

**UE runtime procedure per packet:**

1. Timestamp arrival $T$ as early as possible.
2. Compute $t_j = T + D$.
3. Compute $x = \left\lfloor (t_j - T_0)/T_{\text{int}} \right\rfloor$.
4. Safe iff $x < i + d$; buffer only if safe.

**Design-time responsibilities:**

- Choose conservative $E_{\text{sync}}, E_s, E_r, \Delta T_{\max}$, and $M_{\text{impl}}$ so that $D$ is valid for the intended UE population and operating conditions.

---

## 10. Implementation

### 10.1 CLI Parameters

D and initial sync bounds are now configured via CLI parameters rather than calculated at runtime.

| CLI Option | Default | Description |
|------------|---------|-------------|
| `--tesla-d-bound` | 1510 μs | Upper bound on (sender_time - receiver_time) for safe packet test |
| `--tesla-initial-sync-bound` | 10 μs | Bound for initial time sync verification (no drift yet) |

The default values were pre-calculated using the formula:
$$D = E_{\text{sync}} + (E_s + E_r) \times \Delta T_{\max} + M_{\text{impl}}$$

With defaults: $E_{\text{sync}}=500\mu s$, $E_s=100ppb$, $E_r=10000ppb$, $\Delta T_{\max}=1s$, $M_{\text{impl}}=1000\mu s$ → $D \approx 1510\mu s$

### 10.2 Initial Time Sync Verification

**Status:** Removed (implicit after IBS verification)

With the removal of `timesync_info` from the TESLA extension, explicit initial time sync verification is no longer performed. The rationale:

1. A legitimate gNB does not forge SSB timing
2. Once IBS signature verification succeeds, the gNB is confirmed legitimate
3. Therefore, the SSB-derived timing is implicitly trusted

The `timesync_verified` flag is now set to `true` automatically after successful IBS signature verification.

### 10.3 Default Parameter Values

**File:** `openair3/SECU/tf5_tesla.h`

| Parameter | Default | Rationale |
|-----------|---------|-----------|
| `TF5_DEFAULT_D_BOUND_US` | 1510 μs | Pre-calculated D for typical deployment (see §10.9 for derivation) |
| `TF5_DEFAULT_INITIAL_SYNC_US` | 10 μs | SSB-based sync accuracy (~2× CP margin) |

### 10.4 Two-Stage Verification

1. **Initial verification** (after BLS): Uses `--tesla-initial-sync-bound` since no drift has accumulated
2. **Safe packet test** (ongoing TESLA): Uses `--tesla-d-bound`

### 10.5 Graceful Degradation

If initial time sync verification fails, the UE falls back to **signature-only mode**:
- Each SIB1 is verified via BLS signature
- TESLA MAC verification is bypassed
- This prevents availability attacks via deliberate clock manipulation

### 10.6 State Diagram

```mermaid
flowchart TD
    A[UE Power On] --> B[SSB Sync - PHY<br/>radio time align]
    B --> C[Receive SIB1<br/>record rx_frame, rx_slot]
    C --> D[BLS Verify<br/>first-time UE]
    D --> E{IBS Signature OK?}
    E -->|Yes| F[timesync_verified = true<br/>gNB authenticated, SSB timing trusted]
    E -->|No| G[auth_failed = true<br/>Abort RRC]
    F --> H[TESLA MAC Mode<br/>safe packet + delayed verify]
```

Note: Initial time sync verification is now implicit. Once the gNB is authenticated via IBS signature, its SSB timing is trusted.

### 10.7 Code References

| Function | File | Purpose |
|----------|------|---------|
| `tf5_tesla_ue_safe_packet_test()` | `openair3/SECU/tf5_tesla.c` | Safe packet test (uses D) |
| `tf5_tesla_ue_init()` | `openair3/SECU/tf5_tesla.c` | Initialize UE with D parameters |
| `nr_rrc_process_sib1()` | `openair2/RRC/NR_UE/rrc_UE.c` | SIB1 processing with time sync |

Note: `tf5_tesla_verify_initial_timesync()` has been removed. Time sync is now implicitly verified after successful IBS signature verification.

### 10.8 Configuration

D parameters are configured via command-line options:

```bash
# Using defaults (D=1510us, initial_sync=500us)
./nr-uesoftmodem --tesla-core-mpk /path/to/mpk.bin

# Custom D values (e.g., for challenging RF environments)
./nr-uesoftmodem --tesla-core-mpk /path/to/mpk.bin \
    --tesla-d-bound 3000 \
    --tesla-initial-sync-bound 1000
```

### 10.9 Parameter Rationale

This section documents the standards-based justification for each default parameter value used in the D calculation.

#### Summary Table

| Parameter | Default | Reference | Justification |
|-----------|---------|-----------|---------------|
| $E_{\text{sync}}$ | 10 μs | Design \[1\]\[2\] | ~2× CP duration margin for SSB-based sync |
| $E_s$ | 100 ppb | 3GPP TS 38.104 §6.4.1 | Medium/Local Area BS frequency accuracy requirement |
| $E_r$ | 10000 ppb | 3GPP TS 38.101-1, Industry | Worst-case bound for consumer UE oscillators in idle mode |
| $\Delta T_{\max}$ | 1 s | 3GPP TS 38.331 (DRX cycles) | Realistic bound covering typical DRX scenarios (320ms-2.56s) |
| $M_{\text{impl}}$ | 1000 μs | Design choice | Implementation safety margin (~14 OFDM symbols at 15 kHz SCS) |

#### $E_s$ = 100 ppb (gNB Clock Drift)

**Reference:** 3GPP TS 38.104, Section 6.4.1 "Frequency error"

| BS Type | Frequency Accuracy |
|---------|-------------------|
| Wide Area BS | ±0.05 ppm (50 ppb) |
| Medium Range BS | ±0.1 ppm (100 ppb) |
| Local Area BS | ±0.1 ppm (100 ppb) |

The 100 ppb value corresponds to the Medium/Local Area BS frequency accuracy requirement. This is conservative for Wide Area BS (which has tighter ±50 ppb) but covers a broader range of deployment scenarios.

#### $E_r$ = 10000 ppb (UE Clock Drift)

**References:**
- 3GPP TS 38.101-1, Section 6.4.1 "Frequency error" (connected UE: ±0.1 ppm)
- Industry practice for consumer-grade oscillators

While connected UEs have ±0.1 ppm requirement per TS 38.101-1, during RRC_IDLE/camping with DRX cycles the UE oscillator drifts without network synchronization. Consumer-grade UE oscillators (TCXO) typically have ±2-10 ppm initial tolerance. The 10 ppm (10,000 ppb) is a conservative worst-case bound for:
- Low-cost UE oscillators
- Temperature variations over operating range
- Idle mode drift without frequent re-sync

This matches LTE design assumptions where CFO of 5 ppm was considered for initial cell search.

#### $E_{\text{sync}}$ = 10 μs (Synchronization Error)

**References:**
- \[1\] R. Tuninato, D. Riviello, et al., "A comprehensive study on the synchronization procedure in 5G NR with 3GPP-compliant link-level simulator," *EURASIP J. Wireless Commun. Netw.*, 2023. https://doi.org/10.1186/s13638-023-02317-5
- \[2\] Ericsson, "5G synchronization requirements and solutions," *Ericsson Technology Review*, Nov. 2020. https://www.ericsson.com/en/reports-and-papers/ericsson-technology-review/articles/5g-synchronization-requirements-and-solutions

**Rationale:**

3GPP does not directly specify a UE-side SSB synchronization accuracy bound. Per \[2\], the timing error tolerance is fundamentally determined by the cyclic prefix (CP) duration (4.7 μs at 15 kHz SCS). Simulation studies \[1\] show that PSS-based timing synchronization typically achieves 1-sample precision (~32 ns at 30.72 MHz sampling) under good conditions, but performance degrades significantly under:
- Low SNR (below -6 dB)
- Severe multipath fading channels
- Large carrier frequency offsets

The 10 μs value (~2× CP duration at 15 kHz SCS) provides sufficient margin for worst-case timing estimation errors while remaining practical. This accounts for degraded conditions (low SNR, multipath) during initial cell search, while being much tighter than overly conservative values.

**Hard Physical Limit: Cyclic Prefix Duration**

In OFDM systems, the Cyclic Prefix (CP) absorbs timing errors and multipath delay spread. If timing error exceeds CP duration:
- **Inter-Symbol Interference (ISI)** occurs between adjacent OFDM symbols
- **Inter-Carrier Interference (ICI)** destroys OFDM subcarrier orthogonality
- → Demodulation becomes impossible

| SCS | Normal CP | Extended CP | Reference |
|-----|-----------|-------------|-----------|
| 15 kHz | **4.7 μs** | - | 3GPP TS 38.211 Table 5.3.1-1/2 |
| 30 kHz | **2.3 μs** | - | |
| 60 kHz | **1.2 μs** | 4.2 μs | |
| 120 kHz | **0.59 μs** | - | |

Since SIB1 typically uses 15 kHz SCS, the hard limit is **4.7 μs**. Our 10 μs design value (~2× CP) provides adequate safety margin while remaining practical for TESLA time synchronization requirements.

#### $\Delta T_{\max}$ = 1 s (Validity Horizon)

**Reference:** Typical DRX cycle ranges (3GPP TS 38.331)

This represents the maximum real-time duration for which PHY time alignment is assumed valid without re-synchronization. It is a **validity horizon**, not an actual re-sync frequency.

**UE timing re-sync mechanisms (actual re-sync happens more frequently):**

| Mechanism | Typical Period | Reference |
|-----------|---------------|-----------|
| SSB broadcast | 20 ms (default) | TS 38.213, configurable 5-160 ms |
| DRX wake-up | 320 ms - 2.56 s | TS 38.331, paging DRX cycle |
| SMTC window | 20-160 ms | TS 38.331, RRM measurement timing |
| SIB1 periodicity | 160 ms | TS 38.331 |

Connected UEs track timing continuously via TRS/DMRS. Idle UEs re-sync at each DRX wake-up when they measure SSB for paging. The 1s value covers most practical idle mode DRX scenarios with margin.

**Note:** The previous value of 10.24s (maximum SIB modification period) was overly conservative. With $\Delta T_{\max}$ = 1s, the drift term contributes only ~10 μs to D.

#### $M_{\text{impl}}$ = 1000 μs (Implementation Margin)

**Reference:** Design choice (no specific standard)

Safety margin to absorb implementation uncertainties:
- Residual timestamping quantization/jitter
- Software processing latency variations
- Multipath effects not captured in $E_{\text{sync}}$ model
- Any unmodeled system-level delays

1 ms is approximately 14 OFDM symbols at 15 kHz SCS (or ~56 symbols at 60 kHz). This provides reasonable safety slack without excessive delay in TESLA authentication.