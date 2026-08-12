// radware-worker.js — deploy on Cloudflare Workers (free plan).
// Fresh-record proxy for livethreatmap.radware.com with CORS headers so the
// portfolio globe can read REAL-TIME attacks. It also enriches each record so
// the client can group by country even for pulse-only (webAttacker) records.
//
// HOW TO DEPLOY (5 min, no code needed after this step):
//   1. Go to https://workers.cloudflare.com/  and log in / sign up.
//   2. Click "Create a Worker" -> name it (e.g. radshake -> URL becomes
//      https://radshake.<subdomain>.workers.dev).
//   3. Delete the demo code, paste this whole file, click "Deploy".
//   4. Copy your worker URL into Portfolio/index.html : set
//        const ATK_LIVE_URL = 'https://radshake.<subdomain>.workers.dev';
//   5. Commit + push. Done — map is now truly live, refreshed every 45s.

const TARGET = 'https://livethreatmap.radware.com/api/map/attacks';

export default {
  async fetch(request) {
    const mode = request.cors; // (noop) keep simple
    const q = new URL(request.url).searchParams;
    const limit = q.get('limit') || 80;

    const up = new URL(TARGET);
    up.searchParams.set('limit', limit);

    try {
      const resp = await fetch(up, { headers: { 'accept': 'application/json' } });
      const raw = await resp.json();

      const headers = new Headers({
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Vary': 'Origin',
      });

      if (request.method === 'OPTIONS') {
        return new Response(null, { status: 204, headers });
      }

      let data;
      try { data = JSON.stringify(outputShape(raw)); }
      catch (e) { data = JSON.stringify(raw); }

      return new Response(data, {
        status: resp.status,
        headers,
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: String(err) }), {
        status: 502,
        headers: new Headers({
          'Access-Control-Allow-Origin': '*',
          'Content-Type': 'application/json',
        }),
      });
    }
  },
};

// Normalize the Radware payload — it sometimes wraps the real records in
// { sourceCountry, value: [...] } objects, and webAttackers (pulse-only rows)
// have a blank destinationCountry but DO have a sourceCity we can keep.
function outputShape(payload) {
  const out = [];
  const walk = (node) => {
    if (Array.isArray(node)) { for (const x of node) walk(x); return; }
    if (node && typeof node === 'object') {
      if (node.value && Array.isArray(node.value)) {
        walk(node.value);
        return;
      }
      if (typeof node.sourceCountry === 'string' && node.sourceCountry) {
        out.push({
          sourceCountry: node.sourceCountry,
          destinationCountry: typeof node.destinationCountry === 'string' ? node.destinationCountry : '',
          sourceCity: node.sourceCity || '',
          destinationCity: node.destinationCity || '',
          type: node.type || '',
          weight: Number(node.weight) || 1,
          attackTime: node.attackTime || '',
        });
      } else {
        for (const k in node) walk(node[k]);
      }
    }
  };
  walk(payload);
  return out;
}