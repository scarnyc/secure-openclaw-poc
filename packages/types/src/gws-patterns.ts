/** GWS method classification patterns — single source of truth.
 *  Used by both policy classifier and executor email scanner. */

/** Read method patterns — classified as read */
export const GWS_READ_PATTERNS = /\b(list|get|search|watch)\b/;

/** Write method patterns — classified as write */
export const GWS_WRITE_PATTERNS = /\b(create|insert|update|patch|modify|copy)\b/;

/** Delete/trash method patterns — classified as dangerous */
export const GWS_DELETE_PATTERNS = /\b(delete|trash|remove)\b/;

/** Gmail send/draft-send method patterns — classified as write-irreversible */
export const GMAIL_SEND_PATTERNS = /\b(send|drafts\.send)\b/;

/** Gmail methods that accept email content — used for credential/injection scanning.
 *  Broader than GMAIL_SEND_PATTERNS (which is only for classification as write-irreversible). */
export const GMAIL_CONTENT_PATTERNS = /\b(send|drafts\.send|drafts\.create|drafts\.update)\b/;

/** Calendar create/insert method patterns */
export const CALENDAR_CREATE_PATTERNS = /\b(insert|create)\b/;
