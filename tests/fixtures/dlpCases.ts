// Shared DLP fixtures for python/daemon.py and hooks/dlp.ts (tests/test_daemon.py reads this file too).
// Each text is prefix + filler(n, alphabet) + suffix, built at test time so no token-shaped string is stored.
// The value after the = sign must stay plain JSON.
export const DLP_CASES = [
  {
    "prefix": "AKIA",
    "n": 16,
    "alphabet": "ABC7",
    "category": "SECRET_LEAK_AWS_ACCESS_KEY",
    "hit": true
  },
  {
    "prefix": "AKIA",
    "n": 12,
    "alphabet": "ABC7",
    "category": "SECRET_LEAK_AWS_ACCESS_KEY",
    "hit": false
  },
  {
    "prefix": "gho_",
    "n": 36,
    "alphabet": "Ab3",
    "category": "SECRET_LEAK_GITHUB_TOKEN",
    "hit": true
  },
  {
    "prefix": "ghr_",
    "n": 36,
    "alphabet": "Ab3",
    "category": "SECRET_LEAK_GITHUB_TOKEN",
    "hit": true
  },
  {
    "prefix": "ghx_",
    "n": 36,
    "alphabet": "Ab3",
    "category": "SECRET_LEAK_GITHUB_TOKEN",
    "hit": false
  },
  {
    "prefix": "github_pat_",
    "n": 30,
    "alphabet": "aB3_",
    "category": "SECRET_LEAK_GITHUB_TOKEN",
    "hit": true
  },
  {
    "prefix": "sk-ant-oat01-",
    "n": 40,
    "alphabet": "aB3_-x",
    "category": "SECRET_LEAK_ANTHROPIC_KEY",
    "hit": true
  },
  {
    "prefix": "sk-ant-api03-",
    "n": 40,
    "alphabet": "aB3_-x",
    "suffix": "-_",
    "category": "SECRET_LEAK_ANTHROPIC_KEY",
    "hit": true
  },
  {
    "prefix": "sk-ant-oat01-",
    "n": 10,
    "alphabet": "aB3",
    "category": "SECRET_LEAK_ANTHROPIC_KEY",
    "hit": false
  },
  {
    "prefix": "sk-proj-",
    "n": 30,
    "alphabet": "aB-_",
    "category": "SECRET_LEAK_API_KEY",
    "hit": true
  },
  {
    "prefix": "sk-",
    "n": 40,
    "alphabet": "Ab3",
    "category": "SECRET_LEAK_API_KEY",
    "hit": true
  },
  {
    "prefix": "sk-",
    "n": 20,
    "alphabet": "Ab3",
    "category": "SECRET_LEAK_API_KEY",
    "hit": false
  },
  {
    "prefix": "AIza",
    "n": 35,
    "alphabet": "aB_-",
    "category": "SECRET_LEAK_GCP_API_KEY",
    "hit": true
  },
  {
    "prefix": "xoxb-1234567890-0987654321-",
    "n": 24,
    "alphabet": "Ab3",
    "category": "SECRET_LEAK_SLACK_TOKEN",
    "hit": true
  },
  {
    "prefix": "xoxz-1234567890-0987654321-",
    "n": 8,
    "alphabet": "Ab3",
    "category": "SECRET_LEAK_SLACK_TOKEN",
    "hit": false
  },
  {
    "prefix": "sk_live_",
    "n": 30,
    "alphabet": "Ab3",
    "category": "SECRET_LEAK_STRIPE_KEY",
    "hit": true
  },
  {
    "prefix": "rk_live_",
    "n": 30,
    "alphabet": "Ab3",
    "category": "SECRET_LEAK_STRIPE_KEY",
    "hit": true
  },
  {
    "prefix": "sk_test_",
    "n": 30,
    "alphabet": "Ab3",
    "category": "SECRET_LEAK_STRIPE_KEY",
    "hit": false
  },
  {
    "prefix": "npm_",
    "n": 36,
    "alphabet": "Ab3",
    "category": "SECRET_LEAK_NPM_TOKEN",
    "hit": true
  },
  {
    "prefix": "npm_config_registry",
    "n": 0,
    "alphabet": "x",
    "category": "SECRET_LEAK_NPM_TOKEN",
    "hit": false
  },
  {
    "prefix": "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMII",
    "n": 8,
    "alphabet": "Ab3",
    "category": "SECRET_LEAK_PRIVATE_KEY",
    "hit": true
  },
  {
    "prefix": "{\"private_key\": \"-----BEGIN PRIVATE KEY-----\\nMII",
    "n": 8,
    "alphabet": "Ab3",
    "suffix": "\"}",
    "category": "SECRET_LEAK_PRIVATE_KEY",
    "hit": true
  },
  {
    "prefix": "-----BEGIN PUBLIC KEY-----",
    "n": 0,
    "alphabet": "x",
    "category": "SECRET_LEAK_PRIVATE_KEY",
    "hit": false
  },
  {
    "prefix": "ssn 123-45-6789",
    "n": 0,
    "alphabet": "x",
    "category": "DLP_US_SSN",
    "hit": true
  },
  {
    "prefix": "ssn 000-45-6789",
    "n": 0,
    "alphabet": "x",
    "category": "DLP_US_SSN",
    "hit": false
  }
];
