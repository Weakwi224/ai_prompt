# Security Specification — 나의 AI 프롬프트 창고 (Admin Auth Update)

## 1. Data Invariants
1. **Strict Schema Integrity**: Every document in `/prompts/{promptId}` must contain exactly `title`, `category`, `content`, and `createdAt`—no shadow fields allowed.
2. **Admin-Only Writes**: Only the verified administrator (`request.auth.token.email == 'strongwi224@gmail.com'` and `request.auth.token.email_verified == true`) may `create`, `update`, or `delete` documents in `/prompts`.
3. **Public Guest Read Access**: Unauthenticated visitors may `get` and `list` `/prompts` to browse, search, filter, and copy prompts.
4. **Path ID Hardening**: Every single-document operation (`get`, `create`, `update`, `delete`) validates `promptId` against `^[a-zA-Z0-9_-]+$` and length `1..128`.
5. **Bounded Payloads**: `title` (`1..120`), `category` (`사진 합성`, `스타일 변환`, `캐릭터·포스터`), `content` (`1..20000`).
6. **Temporal & Immutable `createdAt`**: `createdAt` must equal `request.time` on `create` and must remain unchanged (`incoming().createdAt == existing().createdAt`) on `update`, where only `['title', 'category', 'content']` may be modified.
7. **Default-Deny Catch-All**: All unspecified paths under `/databases/{database}/documents` are denied (`allow read, write: if false;`).

## 2. The "Dirty Dozen" Payloads (Expected: PERMISSION_DENIED)
1. **Unauthenticated Create**: Guest calls `addDoc(collection(db, 'prompts'), ...)`
2. **Non-Admin User Create**: Authenticated user with `other@gmail.com` attempts `create`
3. **Unverified Admin Spoof**: Token with `email == 'strongwi224@gmail.com'` and `email_verified == false`
4. **Unauthenticated Update**: Guest attempts `updateDoc` on existing prompt
5. **Unauthenticated Delete**: Guest attempts `deleteDoc` on existing prompt
6. **Ghost Field Injection**: Admin sends `{ ..., isPinned: true }`
7. **Immutable `createdAt` Tampering**: Admin attempts to modify `createdAt` during `update`
8. **Invalid Category**: Admin sends `{ category: '기타' }`
9. **Empty Title / Oversized Title (>120)**: Admin sends `title: ""` or `"a".repeat(121)`
10. **Empty Content / Oversized Content (>20,000)**: Admin sends `content: ""` or `"a".repeat(20001)`
11. **Spoofed Client Timestamp on Create**: Admin sends past `Timestamp` instead of `serverTimestamp()`
12. **Poisoned Document ID**: Admin targets `/prompts/invalid$id@space`
