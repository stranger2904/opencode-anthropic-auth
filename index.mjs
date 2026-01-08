import { generatePKCE } from "@openauthjs/openauth/pkce";
import { promises as fs } from "fs";
import { join } from "path";

const CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

// Logging configuration
const LOG_DIR = process.env.OPENCODE_AUTH_LOG_DIR ||
  join(process.env.HOME || process.env.USERPROFILE || ".", ".opencode-anthropic-logs");
const ENABLE_LOGGING = process.env.OPENCODE_AUTH_LOGGING === "true";

async function ensureLogDirectory() {
  try {
    await fs.mkdir(LOG_DIR, { recursive: true });
  } catch (err) {
    // Directory already exists or permission error - ignore
  }
}

async function logToFile(filename, content) {
  if (!ENABLE_LOGGING) return;

  await ensureLogDirectory();
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const filepath = join(LOG_DIR, `${filename}-${timestamp}.json`);

  try {
    await fs.writeFile(filepath, JSON.stringify(content, null, 2), "utf-8");
  } catch (err) {
    console.error(`Failed to log to file: ${err.message}`);
  }
}

/**
 * @param {"max" | "console"} mode
 */
async function authorize(mode) {
  const pkce = await generatePKCE();

  const url = new URL(
    `https://${mode === "console" ? "console.anthropic.com" : "claude.ai"}/oauth/authorize`,
    import.meta.url,
  );
  url.searchParams.set("code", "true");
  url.searchParams.set("client_id", CLIENT_ID);
  url.searchParams.set("response_type", "code");
  url.searchParams.set(
    "redirect_uri",
    "https://console.anthropic.com/oauth/code/callback",
  );
  url.searchParams.set(
    "scope",
    "org:create_api_key user:profile user:inference",
  );
  url.searchParams.set("code_challenge", pkce.challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", pkce.verifier);
  return {
    url: url.toString(),
    verifier: pkce.verifier,
  };
}

/**
 * @param {string} code
 * @param {string} verifier
 */
async function exchange(code, verifier) {
  const splits = code.split("#");
  const result = await fetch("https://console.anthropic.com/v1/oauth/token", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      code: splits[0],
      state: splits[1],
      grant_type: "authorization_code",
      client_id: CLIENT_ID,
      redirect_uri: "https://console.anthropic.com/oauth/code/callback",
      code_verifier: verifier,
    }),
  });
  if (!result.ok)
    return {
      type: "failed",
    };
  const json = await result.json();
  return {
    type: "success",
    refresh: json.refresh_token,
    access: json.access_token,
    expires: Date.now() + json.expires_in * 1000,
  };
}

/**
 * @type {import('@opencode-ai/plugin').Plugin}
 */
export async function AnthropicAuthPlugin({ client }) {
  return {
    auth: {
      provider: "anthropic",
      async loader(getAuth, provider) {
        const auth = await getAuth();
        if (auth.type === "oauth") {
          // zero out cost for max plan
          for (const model of Object.values(provider.models)) {
            model.cost = {
              input: 0,
              output: 0,
              cache: {
                read: 0,
                write: 0,
              },
            };
          }
          return {
            apiKey: "",
            /**
             * @param {any} input
             * @param {any} init
             */
            async fetch(input, init) {
              const auth = await getAuth();
              if (auth.type !== "oauth") return fetch(input, init);
               if (!auth.access || auth.expires < Date.now()) {
                 // Log token refresh request
                 await logToFile("token-refresh-request", {
                   url: "https://console.anthropic.com/v1/oauth/token",
                   method: "POST",
                   headers: {
                     "Content-Type": "application/json",
                   },
                   body: {
                     grant_type: "refresh_token",
                     refresh_token: "[REDACTED]",
                     client_id: CLIENT_ID,
                   },
                 });

                 const response = await fetch(
                   "https://console.anthropic.com/v1/oauth/token",
                   {
                     method: "POST",
                     headers: {
                       "Content-Type": "application/json",
                     },
                     body: JSON.stringify({
                       grant_type: "refresh_token",
                       refresh_token: auth.refresh,
                       client_id: CLIENT_ID,
                     }),
                   },
                 );

                 if (!response.ok) {
                   const errorText = await response.text();
                   await logToFile("token-refresh-error", {
                     status: response.status,
                     statusText: response.statusText,
                     body: errorText,
                   });
                   throw new Error(`Token refresh failed: ${response.status}`);
                 }

                 const json = await response.json();
                 await logToFile("token-refresh-success", {
                   access_token: "[REDACTED]",
                   refresh_token: "[REDACTED]",
                   expires_in: json.expires_in,
                 });

                 await client.auth.set({
                   path: {
                     id: "anthropic",
                   },
                   body: {
                     type: "oauth",
                     refresh: json.refresh_token,
                     access: json.access_token,
                     expires: Date.now() + json.expires_in * 1000,
                   },
                 });
                 auth.access = json.access_token;
               }
              // Add oauth-2025-04-20 beta to whatever betas are already present
              const incomingBeta = init.headers?.["anthropic-beta"] || "";
              const incomingBetasList = incomingBeta
                .split(",")
                .map((b) => b.trim())
                .filter(Boolean);

              // Add oauth beta and deduplicate
              const mergedBetas = [
                ...new Set([
                  "oauth-2025-04-20",
                  "claude-code-20250219",
                  "interleaved-thinking-2025-05-14",
                  "fine-grained-tool-streaming-2025-05-14",
                  ...incomingBetasList,
                ]),
              ].join(",");

               // Log request before sending
               const requestData = {
                 url: input.toString(),
                 method: init.method || "POST",
                 headers: {
                   ...init.headers,
                   authorization: "[REDACTED]", // Don't log sensitive data
                   "x-api-key": init.headers?.["x-api-key"] ? "[REDACTED]" : undefined,
                 },
                 body: init.body ? (() => {
                   try {
                     return JSON.parse(init.body);
                   } catch {
                     return "[UNPARSEABLE BODY]";
                   }
                 })() : undefined,
               };
               await logToFile("request", requestData);

               const headers = {
                 ...init.headers,
                 authorization: `Bearer ${auth.access}`,
                 "anthropic-beta": mergedBetas,
               };
               delete headers["x-api-key"];

               // Make the actual request
               const response = await fetch(input, {
                 ...init,
                 headers,
               });

               // Log response
               const responseClone = response.clone();
               let responseData;
               try {
                 const responseText = await responseClone.text();
                 responseData = {
                   url: input.toString(),
                   status: response.status,
                   statusText: response.statusText,
                   headers: Object.fromEntries(response.headers.entries()),
                   body: responseText.length > 100000
                     ? "[TRUNCATED - LARGE BODY]"
                     : (() => {
                         try {
                           return JSON.parse(responseText);
                         } catch {
                           return responseText.length > 5000 ? "[UNPARSEABLE LARGE BODY]" : responseText;
                         }
                       })(),
                 };
               } catch (err) {
                 responseData = {
                   url: input.toString(),
                   status: response.status,
                   statusText: response.statusText,
                   error: `Failed to read response: ${err.message}`,
                 };
               }
               await logToFile("response", responseData);

               return response;
            },
          };
        }

        return {};
      },
      methods: [
        {
          label: "Claude Pro/Max",
          type: "oauth",
          authorize: async () => {
            const { url, verifier } = await authorize("max");
            return {
              url: url,
              instructions: "Paste the authorization code here: ",
              method: "code",
              callback: async (code) => {
                const credentials = await exchange(code, verifier);
                return credentials;
              },
            };
          },
        },
        {
          label: "Create an API Key",
          type: "oauth",
          authorize: async () => {
            const { url, verifier } = await authorize("console");
            return {
              url: url,
              instructions: "Paste the authorization code here: ",
              method: "code",
              callback: async (code) => {
                const credentials = await exchange(code, verifier);
                if (credentials.type === "failed") return credentials;
                const result = await fetch(
                  `https://api.anthropic.com/api/oauth/claude_cli/create_api_key`,
                  {
                    method: "POST",
                    headers: {
                      "Content-Type": "application/json",
                      authorization: `Bearer ${credentials.access}`,
                    },
                  },
                ).then((r) => r.json());
                return { type: "success", key: result.raw_key };
              },
            };
          },
        },
        {
          provider: "anthropic",
          label: "Manually enter API Key",
          type: "api",
        },
      ],
    },
  };
}
