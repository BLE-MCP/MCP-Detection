#!/bin/bash

# Reset tokens script for Dropbox MCP Server
# This script resets the tokens file with the current encryption key
# Use this if you encounter decryption errors when starting the server

echo "Resetting Dropbox MCP Server tokens..."
node build/src/reset-tokens.js

echo ""
echo "After running this script, you may need to re-authorize the application"
echo "when you next start the server."
echo ""
echo "To start the server, run: npm start"
