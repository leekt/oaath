---
"@oaath/protocol": minor
"@oaath/sdk": minor
---

Expose an exact immutable UserOperation reference codec and a read-only observer
for applications that own their operation journals. The observer shares OAAth's
receipt, transaction, canonical block and finality verification, including saved
direct transaction hints. It neither creates Grants or Operations nor signs,
submits, checks replacements, or authorizes a retry. Pending and unreadable
evidence keep the saved identity unresolved.
