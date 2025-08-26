/** @type {import('@jest/types').Config.InitialOptions} */
module.exports = {
    testEnvironment: 'node',
    transform: {
        '^.+\\.(t|j)sx?$': [
            'babel-jest',
            {
                // Add this to handle ESM modules
                plugins: [
                    ['@babel/plugin-syntax-import-meta'],
                    ['@babel/plugin-transform-modules-commonjs', { allowTopLevelThis: true }],
                    ['@babel/plugin-proposal-class-properties', { loose: true }],
                    ['@babel/plugin-transform-runtime', { regenerator: true }]
                ]
            }
        ]
    },
    transformIgnorePatterns: [
        'node_modules/(?!(@modelcontextprotocol|zod)/)'
    ],
    moduleNameMapper: {
        '^(\\.{1,2}/.*)\\.js$': '$1'
    },
    moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
    testMatch: [
        '<rootDir>/tests/**/*.test.ts'
    ],
    // Run setup.ts after the environment is set up
    setupFilesAfterEnv: [
        '<rootDir>/tests/setup.ts'
    ],
    globals: {
        'ts-jest': {
            useESM: true
        }
    },
    // Show console output but with less verbosity
    verbose: false,
    // Add this to handle ESM modules
    extensionsToTreatAsEsm: ['.ts', '.tsx'],
    // Mock the import.meta.url
    testEnvironmentOptions: {
        customExportConditions: ['node', 'node-addons']
    },
    // Use resolver that can handle both ESM and CommonJS
    resolver: 'jest-ts-webcompat-resolver',
    // Improve error reporting to troubleshoot module issues
    forceExit: true,
    // Add more detail to the test output
    testRunner: 'jest-circus/runner'
};
