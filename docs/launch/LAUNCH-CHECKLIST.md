# Glassbox launch checklist

## Launch objective

Find ten agent developers or operators willing to run the demo and explain which actions need receipts or rollback. Stars and impressions are secondary to completed demos and concrete integration feedback.

## Before posting

- [x] Public Apache-2.0 repository
- [x] Tagged release with wheel, sdist, and checksums
- [x] Security policy and private vulnerability reporting
- [x] Python 3.11–3.13 CI and CodeQL
- [x] Secret scanning and push protection
- [x] Dashboard screenshot and repeatable synthetic walkthrough
- [x] Public alpha-feedback issue
- [ ] Re-read every post against the current README
- [ ] Confirm the latest CI run is green
- [ ] Open every link in an anonymous browser session
- [ ] Run the quick start from a fresh clone

## Recommended sequence

### Day 1: technical launch

1. Publish the long-form article.
2. Submit the Show HN post between the beginning and middle of the US workday.
3. Stay available for several hours to answer technical questions.
4. Answer limitations directly; do not argue with criticism or ask for votes.

### Day 2: communities

1. Post the tailored version to `r/LocalLLaMA` if self-promotion rules permit it.
2. Post the self-hosting version to `r/selfhosted` on a different day or with materially different context.
3. Share the short demo on X and LinkedIn.
4. Avoid posting identical copy across communities.

### Days 3–7: design partners

1. Contact no more than five relevant developers per day.
2. Mention the specific project or workflow that makes the outreach relevant.
3. Ask for a 20–30 minute workflow interview, not an endorsement.
4. Stop after one follow-up if there is no response.
5. Record only non-sensitive findings and ask before quoting anyone publicly.

### Week 2

1. Group feedback by installation, integration, receipt schema, rollback scope, and trust requirements.
2. Build the most frequently requested narrow integration.
3. Publish what changed because of user feedback.

## Community etiquette

- Read each community’s current self-promotion rules before posting.
- Lead with a problem and a working demonstration, not a star request.
- Disclose that you built Glassbox.
- Do not cross-post the same text simultaneously.
- Never manufacture votes, comments, testimonials, usage, or urgency.
- Route suspected vulnerabilities to private reporting immediately.

## Weekly metrics

| Metric | Why it matters |
|---|---|
| Quick-start completions | Measures whether people can reach the product |
| First receipt created | Measures activation rather than page views |
| First successful or safely refused rollback | Tests the core value proposition |
| Feedback issue participants | Indicates useful interest |
| Integration requests with a named framework | Guides distribution work |
| Repeat contributors | Indicates durable community value |

GitHub stars, article views, and social impressions are useful context but are not primary success criteria for the alpha.

## Feedback links

- Public alpha feedback: <https://github.com/jckm14/glassbox/issues/8>
- Non-security bugs: <https://github.com/jckm14/glassbox/issues/new/choose>
- Private security reports: <https://github.com/jckm14/glassbox/security/advisories/new>
