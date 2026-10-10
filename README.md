# Project ASTRA

> **A**uthenticated **S**ignature & **T**XT **R**ecord **A**nalyzer

**Project ASTRA** is a high-performance, lightweight, and asynchronous DKIM (DomainKeys Identified Mail) lookup tool written in Python. It allows cybersecurity researchers, OSINT analysts, and system administrators to quickly discover and inspect active DKIM public keys across target domains using parallel DNS resolution.

---

## Features

- **Asynchronous Execution:** Built on top of `asyncio` and `dnspython` for maximum throughput and minimal overhead.
- **Selector Enumeration:** Quickly probes common Email Service Provider (ESP) selectors concurrently.
- **Custom Selectors:** Accepts custom list inputs for targeted reconnaissance.
- **Zero Heavy Dependencies:** Extremely lightweight codebase with minimal external packages.

---
