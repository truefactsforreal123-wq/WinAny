# Deploy

Needs a Cloudflare account and a Realtime TURN key (dashboard > Realtime > TURN).

```
cd server
npm install
npm test && npm run typecheck
npx wrangler login
npx wrangler secret put TURN_KEY_ID
npx wrangler secret put TURN_KEY_API_TOKEN
npx wrangler deploy          # applies migration v1 (SignalingHub, SQLite DO)
npx wrangler tail            # logs
```

- TURN daily budget: edit `TURN_DAILY_BUDGET` under `[vars]` in `wrangler.toml`, then redeploy. Unset or `0` disables TURN.
- Client URL: `wss://remote-signaling.<your-subdomain>.workers.dev/v1/ws`.
- Local run: `npx wrangler dev` (put local secrets in `server/.dev.vars`, git-ignored).
- New DO classes or renames need a new `[[migrations]]` tag (v2, ...); never edit v1.
