# PromptWall — Adaptive AI Security Gateway

PromptWall is an extensible AI security gateway that sits between applications and LLM providers to inspect, analyze, and enforce security policies on incoming prompts before they reach external AI services.

It provides a modular security pipeline for detecting sensitive information, secrets, prompt injection attempts, and other AI-specific threats while maintaining an extensible architecture for future security detectors and policies.

---

## Architecture

```text
                    Client / Application
                           |
                           v
                 +----------------------+
                 |   PromptWall Gateway |
                 |     Bun + Hono       |
                 +----------+-----------+
                            |
                            v
                 +----------------------+
                 |  Request Extraction  |
                 |   OpenAI-compatible   |
                 |       API Layer       |
                 +----------+-----------+
                            |
                            v
              +-----------------------------+
              |     Detection Pipeline      |
              +-----------------------------+
                            |
                            v
                 +----------------------+
                 |  Detector Registry   |
                 +----------+-----------+
                            |
          +-----------------+------------------+
          |                 |                  |
          v                 v                  v
   Secret Detection   PII Detection    Injection Detection
      Regex/Entropy      GLiNER             Rules/Model
          |                 |                  |
          +-----------------+------------------+
                            |
                            v
                 +----------------------+
                 |   Candidate Graph    |
                 |  Evidence Resolution |
                 +----------+-----------+
                            |
                            v
                 +----------------------+
                 |   Confidence Engine  |
                 +----------+-----------+
                            |
                            v
                 +----------------------+
                 |     Risk Engine      |
                 |  Weighted Risk Fusion |
                 +----------+-----------+
                            |
                            v
                 +----------------------+
                 |    Policy Engine     |
                 +----------+-----------+
                            |
                   +--------+--------+
                   |        |        |
                 ALLOW     MASK     BLOCK
                   |        |        |
                   +--------+--------+
                            |
                            v
                 +----------------------+
                 | Provider Abstraction |
                 +----------+-----------+
                            |
              +-------------+-------------+
              |             |             |
            OpenAI       Gemini        Anthropic
              |                           |
              +----------+----------------+
                         |
                         v
                  LLM Provider
                         |
                         v
                 Response Inspection
                         |
                         v
                       Client
