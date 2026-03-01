# BlueSPY MCP Demo Prompts

Curated prompts for demo videos, LinkedIn content, and newsletter showcases. Designed to highlight the unique combination of live Bluetooth LE packet analysis (bluespy-mcp) with AI-powered spec cross-referencing (bluetooth-spec-mcp).

---

## Tier 1: High Impact

These create the strongest "wow factor" — lead with these in demos and social content.

### 1. Live Debug Detective

> Connect to the sniffer and start capturing. I have a device nearby that keeps disconnecting. Watch the traffic and tell me WHY it's disconnecting — cross-reference the error codes with the Bluetooth spec.

**What it demonstrates:** AI watches live traffic, spots the disconnect reason, looks up the error code in the Bluetooth Core Specification, and explains the root cause — all conversationally.

**Pain point it solves:** This is hours of Wireshark filtering + manual spec lookup compressed into a 30-second conversation.

**Best for:** Video demos, LinkedIn posts about developer productivity.

---

### 2. The Spec Copilot

> Load this capture file. I see ATT errors in there — find them, explain what each error code means according to the Bluetooth Core Specification, and tell me if my peripheral is violating the spec.

**What it demonstrates:** The bridge between raw packet data and the 3,000+ page Bluetooth Core Specification. Two MCP servers working together — one analyzing packets, one querying the spec.

**Pain point it solves:** Nobody reads the full spec for fun. This cross-references automatically and gives actionable answers.

**Best for:** Technical audience content, newsletter deep-dives.

---

### 3. Live Security Audit

> Connect to the sniffer, start capturing, and give me a security audit of every Bluetooth LE device advertising near me. What are they broadcasting? Are any of them exposing sensitive information in their advertising data?

**What it demonstrates:** Real-time environmental scanning with security analysis. AI identifies every broadcasting device and evaluates what data they're exposing.

**Pain point it solves:** Privacy/security auditing of Bluetooth LE deployments is tedious and requires deep protocol knowledge.

**Best for:** LinkedIn (security angle gets high engagement), conference demos. Makes the audience immediately think about their own products.

---

## Tier 2: Developer Pain Points

Relatable scenarios that every Bluetooth LE developer has faced.

### 4. Connection Parameter Review

> Capture for 10 seconds, then find all connections and tell me if the connection parameters are reasonable for a low-power sensor application. What would you recommend changing?

**What it demonstrates:** AI analyzes connection intervals, slave latency, and supervision timeout — then gives optimization recommendations for the specific use case.

**Pain point it solves:** Connection interval tuning is one of the most common Bluetooth LE optimization challenges. Getting it wrong kills battery life or throughput.

**Best for:** Tutorial-style content, developer-focused newsletter sections.

---

### 5. Channel Distribution Analysis

> Start capturing and show me the advertising channel distribution for the loudest device. Is it using all three advertising channels evenly, or is something wrong with its RF?

**What it demonstrates:** Statistical analysis of advertising behavior across channels 37, 38, and 39. AI spots imbalances that could indicate hardware RF issues.

**Pain point it solves:** Channel imbalance is a subtle hardware issue that's nearly impossible to catch by scrolling through packets manually.

**Best for:** Technical deep-dive content, hardware debugging showcases.

---

### 6. The "Explain It to My PM" Prompt

> Load this capture file. Summarize what happened in this Bluetooth LE session in plain English — no jargon. I need to explain a connection failure to my product manager.

**What it demonstrates:** AI translates raw protocol data into a non-technical narrative. Connection lifecycle, what went wrong, and why — in language anyone can understand.

**Pain point it solves:** Every developer has been asked to explain a protocol-level issue to a non-technical stakeholder.

**Best for:** LinkedIn (highly relatable, broad appeal), email newsletter hooks.

---

## Tier 3: Advanced / Niche

For the deep technical audience — conference talks, advanced tutorials, power-user showcases.

### 7. Multi-Device Triage

> Start capturing. There are multiple devices nearby. Find all of them, rank them by advertising frequency, and tell me which one is the most aggressive advertiser and how much power it's probably wasting.

**What it demonstrates:** Multi-device environment analysis with quantitative comparison. AI ranks devices by behavior and estimates power impact.

**Pain point it solves:** In dense Bluetooth LE environments (smart homes, warehouses, hospitals), identifying the noisiest device is critical for debugging interference and optimizing power.

---

### 8. Protocol Forensics

> Load this capture. Walk me through the entire connection lifecycle — from the first ADV_IND to the TERMINATE_IND. What happened at each stage? Was the pairing sequence correct?

**What it demonstrates:** Full protocol timeline reconstruction with spec compliance checking at each stage. AI narrates the connection like a story.

**Pain point it solves:** Understanding a full connection lifecycle from raw packets requires deep protocol knowledge and patience. AI does the correlation automatically.

---

### 9. Real-Time Error Watch

> Connect and start capturing. Every few seconds, search for any new error packets. I'm about to trigger a firmware bug — tell me the moment something goes wrong.

**What it demonstrates:** Live monitoring mode where AI acts as a real-time protocol watchdog. Captures the exact moment a bug manifests in the Bluetooth LE traffic.

**Pain point it solves:** Reproducing intermittent firmware bugs while simultaneously analyzing traffic is a two-person job. This makes it a one-person conversation.

---

## Demo Video Structure

For maximum impact in a 90-second video:

| Segment | Duration | Content |
|---------|----------|---------|
| Hook | 5s | "What if you could debug Bluetooth LE by just... asking?" |
| Pain | 10s | Show Wireshark with thousands of packets, overwhelming filters |
| Demo 1 | 30s | Prompt #1 or #3 — live capture with instant analysis |
| Demo 2 | 30s | Prompt #2 — spec cross-reference (two AI tools working together) |
| CTA | 10s | Link to the tool / newsletter signup |

## LinkedIn Performance Notes

- **Highest engagement potential:** #1, #3, #6 — visual, relatable, clear before/after contrast
- **Security angle (#3)** tends to get shares beyond the Bluetooth LE niche
- **PM translation (#6)** resonates with engineering managers and team leads
- **Live demos (#1, #3, #9)** are more compelling than file-based analysis for video content
