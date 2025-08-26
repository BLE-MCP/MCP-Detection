"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var readline = require("readline");
var crypto_1 = require("crypto");
var fs = require("fs");
var auth_js_1 = require("./auth.js");
var security_utils_js_1 = require("./security-utils.js");
var open_1 = require("open");
// Create readline interface for user input
var rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});
// Promisify readline question
var question = function (query) {
    return new Promise(function (resolve) {
        rl.question(query, resolve);
    });
};
// This function has been removed as it's no longer used
function setup() {
    return __awaiter(this, void 0, void 0, function () {
        var tokenEncryptionKey, appKey, appSecret, encryptedSecret, envContent, _a, authUrl, codeVerifier, authCode, tokenData, choice, serverConfig, homedir, claudePath, clinePath, claudeConfig, fileContent, backupPath, parsedConfig, _i, _b, _c, key, value, clineConfig, fileContent, backupPath, parsedConfig, _d, _e, _f, key, value, error_1;
        return __generator(this, function (_g) {
            switch (_g.label) {
                case 0:
                    console.log('\n=== Dropbox MCP Server Setup ===\n');
                    // Clean up any existing tokens file
                    if (fs.existsSync('.tokens.json')) {
                        console.log('Removing existing tokens file...');
                        fs.unlinkSync('.tokens.json');
                    }
                    tokenEncryptionKey = (0, crypto_1.randomBytes)(32).toString('base64');
                    process.env.TOKEN_ENCRYPTION_KEY = tokenEncryptionKey;
                    // Get Dropbox credentials from user
                    console.log('Please enter your Dropbox API credentials:');
                    return [4 /*yield*/, question('App Key: ')];
                case 1:
                    appKey = _g.sent();
                    return [4 /*yield*/, question('App Secret: ')];
                case 2:
                    appSecret = _g.sent();
                    encryptedSecret = (0, security_utils_js_1.encryptData)(appSecret);
                    envContent = "DROPBOX_APP_KEY=".concat(appKey, "\nDROPBOX_APP_SECRET=").concat(JSON.stringify(encryptedSecret), "\nDROPBOX_REDIRECT_URI=http://localhost\nTOKEN_ENCRYPTION_KEY=").concat(tokenEncryptionKey, "\nCORS_ALLOWED_ORIGINS=http://localhost:3000\nTOKEN_REFRESH_THRESHOLD_MINUTES=5\nMAX_TOKEN_REFRESH_RETRIES=3\nTOKEN_REFRESH_RETRY_DELAY_MS=1000\nTOKEN_STORE_PATH=.tokens.json\nDROPBOX_RECYCLE_BIN_PATH=/.recycle_bin\nDROPBOX_MAX_DELETES_PER_DAY=100\nDROPBOX_RETENTION_DAYS=30\nDROPBOX_ALLOWED_PATHS=/\nDROPBOX_BLOCKED_PATHS=/.recycle_bin,/.system");
                    // Write .env file
                    fs.writeFileSync('.env', envContent);
                    console.log('\n✅ Created .env file with encrypted app secret');
                    // Set environment variables for auth
                    process.env.DROPBOX_APP_KEY = appKey;
                    process.env.DROPBOX_APP_SECRET = appSecret;
                    process.env.DROPBOX_REDIRECT_URI = 'http://localhost';
                    _a = (0, auth_js_1.generateAuthUrl)(), authUrl = _a.url, codeVerifier = _a.codeVerifier;
                    // Open auth URL in browser
                    console.log('\nOpening authorization URL in your browser...');
                    return [4 /*yield*/, (0, open_1.default)(authUrl)];
                case 3:
                    _g.sent();
                    // Get authorization code from user
                    console.log('\nPlease authorize the application in your browser.');
                    console.log('After authorization, you will be redirected to a URL containing the authorization code.');
                    console.log('Copy the "code" parameter from the URL and paste it here.');
                    return [4 /*yield*/, question('\nAuthorization code: ')];
                case 4:
                    authCode = _g.sent();
                    _g.label = 5;
                case 5:
                    _g.trys.push([5, 8, , 9]);
                    // Exchange code for tokens
                    console.log('\nExchanging authorization code for tokens...');
                    return [4 /*yield*/, (0, auth_js_1.exchangeCodeForTokens)(authCode, codeVerifier)];
                case 6:
                    tokenData = _g.sent();
                    console.log('\n✅ Successfully obtained and stored access token');
                    console.log('Token details:');
                    console.log('- Access token expires:', new Date(tokenData.expiresAt).toLocaleString());
                    console.log('- Scopes:', tokenData.scope.join(', '));
                    // Ask about generating config files
                    console.log('\nWould you like to generate MCP configuration files?');
                    console.log('1. Generate Claude Desktop config');
                    console.log('2. Generate Cline config');
                    console.log('3. Generate both');
                    console.log('4. Skip');
                    return [4 /*yield*/, question('\nEnter your choice (1-4): ')];
                case 7:
                    choice = _g.sent();
                    if (choice === '1' || choice === '2' || choice === '3') {
                        serverConfig = {
                            command: "node",
                            args: ["".concat(process.cwd(), "/build/src/index.js")],
                            env: {
                                DROPBOX_APP_KEY: appKey,
                                DROPBOX_APP_SECRET: encryptedSecret,
                                DROPBOX_REDIRECT_URI: "http://localhost",
                                TOKEN_ENCRYPTION_KEY: tokenEncryptionKey,
                                CORS_ALLOWED_ORIGINS: "http://localhost",
                                TOKEN_REFRESH_THRESHOLD_MINUTES: "5",
                                MAX_TOKEN_REFRESH_RETRIES: "3",
                                TOKEN_REFRESH_RETRY_DELAY_MS: "1000",
                                TOKEN_STORE_PATH: "".concat(process.cwd(), "/.tokens.json"),
                                DROPBOX_RECYCLE_BIN_PATH: "/.recycle_bin",
                                DROPBOX_MAX_DELETES_PER_DAY: "100",
                                DROPBOX_RETENTION_DAYS: "30",
                                DROPBOX_ALLOWED_PATHS: "/",
                                DROPBOX_BLOCKED_PATHS: "/.recycle_bin,/.system"
                            },
                            disabled: false,
                            autoApprove: []
                        };
                        homedir = process.env.HOME || '/Users/Amgad';
                        claudePath = "".concat(homedir, "/Library/Application Support/Claude/claude_desktop_config.json");
                        clinePath = "".concat(homedir, "/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json");
                        // Generate Claude Desktop config if selected
                        if (choice === '1' || choice === '3') {
                            claudeConfig = {
                                globalShortcut: "Shift+Cmd+L",
                                mcpServers: {}
                            };
                            // Read existing Claude config if it exists
                            if (fs.existsSync(claudePath)) {
                                try {
                                    fileContent = fs.readFileSync(claudePath, 'utf8');
                                    console.log('\nExisting Claude config found');
                                    backupPath = "".concat(claudePath, ".bak.").concat(Date.now());
                                    fs.writeFileSync(backupPath, fileContent);
                                    console.log("\u2705 Backed up existing Claude config to: ".concat(backupPath));
                                    parsedConfig = JSON.parse(fileContent);
                                    // Debug logging to understand the structure
                                    console.log('\nClaude config keys:', Object.keys(parsedConfig));
                                    if (parsedConfig.mcpServers) {
                                        console.log('Existing Claude MCP servers:', Object.keys(parsedConfig.mcpServers));
                                    }
                                    else {
                                        console.log('No existing mcpServers found in Claude config');
                                    }
                                    // IMPORTANT: Preserve the original structure but ensure we have mcpServers
                                    // This approach maintains any existing config properties
                                    claudeConfig = parsedConfig;
                                    if (!claudeConfig.mcpServers) {
                                        claudeConfig.mcpServers = {};
                                    }
                                    // Ensure we have globalShortcut
                                    if (!claudeConfig.globalShortcut) {
                                        claudeConfig.globalShortcut = "Shift+Cmd+L";
                                    }
                                    // Check for server configs at root level and move them
                                    for (_i = 0, _b = Object.entries(parsedConfig); _i < _b.length; _i++) {
                                        _c = _b[_i], key = _c[0], value = _c[1];
                                        if (key !== 'mcpServers' &&
                                            key !== 'globalShortcut' &&
                                            typeof value === 'object' &&
                                            value !== null &&
                                            'command' in value) {
                                            console.log("Moving root-level MCP server '".concat(key, "' into mcpServers"));
                                            claudeConfig.mcpServers[key] = value;
                                            delete claudeConfig[key];
                                        }
                                    }
                                    // Clean up any misplaced entries
                                    if (claudeConfig.mcpServers.disabled !== undefined) {
                                        console.log('Removing misplaced disabled property from mcpServers');
                                        delete claudeConfig.mcpServers.disabled;
                                    }
                                    if (claudeConfig.mcpServers.autoApprove !== undefined) {
                                        console.log('Removing misplaced autoApprove property from mcpServers');
                                        delete claudeConfig.mcpServers.autoApprove;
                                    }
                                    // This section is redundant and has been removed
                                    // Log all servers we're preserving
                                    console.log('Claude MCP servers after normalization:', Object.keys(claudeConfig.mcpServers));
                                }
                                catch (error) {
                                    console.log('Warning: Could not parse existing Claude config, creating new one');
                                    console.error('Error details:', error);
                                }
                            }
                            // Add our server config
                            console.log('Adding dropbox-mcp-server to Claude config');
                            claudeConfig.mcpServers["dropbox-mcp-server"] = serverConfig;
                            // Write config file
                            fs.mkdirSync("".concat(homedir, "/Library/Application Support/Claude"), { recursive: true });
                            fs.writeFileSync(claudePath, JSON.stringify(claudeConfig, null, 2));
                            console.log('✅ Updated/created Claude Desktop config at:', claudePath);
                        }
                        // Generate Cline config if selected
                        if (choice === '2' || choice === '3') {
                            clineConfig = { mcpServers: {} };
                            // Read existing Cline config if it exists
                            if (fs.existsSync(clinePath)) {
                                try {
                                    fileContent = fs.readFileSync(clinePath, 'utf8');
                                    console.log('\nExisting Cline config found');
                                    backupPath = "".concat(clinePath, ".bak.").concat(Date.now());
                                    fs.writeFileSync(backupPath, fileContent);
                                    console.log("\u2705 Backed up existing Cline config to: ".concat(backupPath));
                                    parsedConfig = JSON.parse(fileContent);
                                    // Debug logging
                                    console.log('\nCline config keys:', Object.keys(parsedConfig));
                                    if (parsedConfig.mcpServers) {
                                        console.log('Existing Cline MCP servers:', Object.keys(parsedConfig.mcpServers));
                                    }
                                    else {
                                        console.log('No existing mcpServers found in Cline config');
                                    }
                                    // IMPORTANT: Preserve the original structure but ensure we have mcpServers
                                    clineConfig = parsedConfig;
                                    if (!clineConfig.mcpServers) {
                                        console.log('Creating mcpServers object in Cline config');
                                        clineConfig.mcpServers = {};
                                    }
                                    // Check for server configs at root level and move them
                                    for (_d = 0, _e = Object.entries(parsedConfig); _d < _e.length; _d++) {
                                        _f = _e[_d], key = _f[0], value = _f[1];
                                        if (key !== 'mcpServers' &&
                                            typeof value === 'object' &&
                                            value !== null &&
                                            'command' in value) {
                                            console.log("Moving root-level MCP server '".concat(key, "' into mcpServers"));
                                            clineConfig.mcpServers[key] = value;
                                            delete clineConfig[key];
                                        }
                                    }
                                    // Clean up any misplaced entries
                                    if (clineConfig.mcpServers.disabled !== undefined) {
                                        console.log('Removing misplaced disabled property from mcpServers');
                                        delete clineConfig.mcpServers.disabled;
                                    }
                                    if (clineConfig.mcpServers.autoApprove !== undefined) {
                                        console.log('Removing misplaced autoApprove property from mcpServers');
                                        delete clineConfig.mcpServers.autoApprove;
                                    }
                                    // This section is redundant and has been removed
                                    // Log all servers we're preserving
                                    console.log('Cline MCP servers after normalization:', Object.keys(clineConfig.mcpServers));
                                }
                                catch (error) {
                                    console.log('Warning: Could not parse existing Cline config, creating new one');
                                    console.error('Error details:', error);
                                }
                            }
                            // Add our server config
                            console.log('Adding dropbox-mcp-server to Cline config');
                            clineConfig.mcpServers["dropbox-mcp-server"] = serverConfig;
                            // Write config file
                            fs.mkdirSync("".concat(homedir, "/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings"), { recursive: true });
                            fs.writeFileSync(clinePath, JSON.stringify(clineConfig, null, 2));
                            console.log('✅ Updated/created Cline config at:', clinePath);
                        }
                    }
                    console.log('\n✅ Setup completed successfully!');
                    console.log('\nYou can now start the server with:');
                    console.log('npm start');
                    return [3 /*break*/, 9];
                case 8:
                    error_1 = _g.sent();
                    console.error('\n❌ Error exchanging authorization code for tokens:', error_1);
                    console.log('Please try the setup process again.');
                    return [3 /*break*/, 9];
                case 9:
                    rl.close();
                    return [2 /*return*/];
            }
        });
    });
}
// Run setup
setup().catch(console.error);
