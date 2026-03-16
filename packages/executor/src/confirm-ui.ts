import type { PolicyDecision } from "@sentinel/types";
import { redactAll } from "@sentinel/types";
import type { Context } from "hono";

interface PendingConfirmationView {
	manifest: { id: string; tool: string; parameters: Record<string, unknown> };
	decision: PolicyDecision;
}

export function createConfirmUiHandler(
	pendingConfirmations: Map<string, PendingConfirmationView>,
	confirmBaseUrl: string,
): (c: Context) => Response {
	return (c: Context): Response => {
		const manifestId = c.req.param("manifestId") ?? "";
		const pending = pendingConfirmations.get(manifestId);

		if (!pending) {
			return c.html(
				renderPage(
					"Not Found",
					'<div class="card"><h2>Confirmation not found</h2><p>This confirmation may have expired, already been resolved, or the ID is invalid.</p></div>',
				),
				404,
			);
		}

		const { manifest, decision } = pending;
		const redactedParams = redactAll(JSON.stringify(manifest.parameters, null, 2));
		const isIrreversible = decision.category === "write-irreversible";
		const confirmUrl = `${confirmBaseUrl}/confirm/${manifestId}`;

		const body = `
<div class="card">
	<h2>Action Requires Confirmation</h2>
	${isIrreversible ? '<div class="warning">THIS ACTION CANNOT BE UNDONE</div>' : ""}
	<div class="detail"><span class="label">Tool:</span> <code>${escapeHtml(manifest.tool)}</code></div>
	<div class="detail"><span class="label">Category:</span> <span class="category-${escapeHtml(decision.category)}">${escapeHtml(decision.category)}</span></div>
	<div class="detail"><span class="label">Reason:</span> ${escapeHtml(decision.reason)}</div>
	<div class="detail"><span class="label">Parameters:</span></div>
	<pre>${escapeHtml(redactedParams)}</pre>
	<div class="actions" id="actions">
		<button class="btn approve" onclick="resolve(true)">Approve</button>
		<button class="btn deny" onclick="resolve(false)">Deny</button>
	</div>
	<div id="result" style="display:none"></div>
</div>
<script>
async function resolve(approved) {
	const actions = document.getElementById('actions');
	const result = document.getElementById('result');
	actions.style.display = 'none';
	try {
		const tokenParams = window.location.search;
		const res = await fetch(${JSON.stringify(confirmUrl)} + tokenParams, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ approved })
		});
		const data = await res.json();
		if (res.ok) {
			result.className = approved ? 'result-approved' : 'result-denied';
			result.textContent = approved ? 'Approved' : 'Denied';
		} else {
			result.className = 'result-error';
			result.textContent = data.error || 'Failed';
			actions.style.display = 'flex';
		}
	} catch (e) {
		result.className = 'result-error';
		result.textContent = 'Network error: ' + e.message;
		actions.style.display = 'flex';
	}
	result.style.display = 'block';
}
</script>`;

		return c.html(renderPage(`Confirm: ${escapeHtml(manifest.tool)}`, body), 200);
	};
}

function renderPage(title: string, body: string): string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sentinel — ${title}</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; background: #0f172a; color: #e2e8f0; padding: 16px; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
.card { background: #1e293b; border-radius: 12px; padding: 24px; max-width: 600px; width: 100%; box-shadow: 0 4px 24px rgba(0,0,0,0.3); }
h2 { font-size: 1.25rem; margin-bottom: 16px; color: #f1f5f9; }
.warning { background: #7f1d1d; border: 1px solid #dc2626; border-radius: 8px; padding: 12px; margin-bottom: 16px; font-weight: 600; text-align: center; color: #fca5a5; }
.detail { margin-bottom: 8px; }
.label { color: #94a3b8; font-weight: 500; }
code { background: #334155; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; }
pre { background: #0f172a; border: 1px solid #334155; border-radius: 8px; padding: 12px; margin: 8px 0 16px; overflow-x: auto; font-size: 0.85em; white-space: pre-wrap; word-break: break-word; }
.actions { display: flex; gap: 12px; margin-top: 16px; }
.btn { flex: 1; padding: 12px; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: opacity 0.2s; }
.btn:hover { opacity: 0.85; }
.approve { background: #16a34a; color: white; }
.deny { background: #dc2626; color: white; }
.result-approved { background: #166534; border-radius: 8px; padding: 12px; text-align: center; font-weight: 600; color: #86efac; margin-top: 16px; }
.result-denied { background: #7f1d1d; border-radius: 8px; padding: 12px; text-align: center; font-weight: 600; color: #fca5a5; margin-top: 16px; }
.result-error { background: #78350f; border-radius: 8px; padding: 12px; text-align: center; font-weight: 600; color: #fde68a; margin-top: 16px; }
.category-write { color: #fbbf24; }
.category-write-irreversible { color: #f87171; font-weight: 600; }
.category-dangerous { color: #ef4444; font-weight: 700; }
.category-read { color: #34d399; }
</style>
</head>
<body>${body}</body>
</html>`;
}

function escapeHtml(str: string): string {
	return str
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;")
		.replace(/'/g, "&#39;");
}

// Exported for testing
export { escapeHtml as _escapeHtml };
