module.exports = {
    presets: [
        ['@babel/preset-env', {
            targets: { node: 'current' },
            modules: 'commonjs' // Explicitly set to commonjs
        }],
        '@babel/preset-typescript',
    ],
    plugins: [
        // Add support for import.meta.url in tests
        '@babel/plugin-syntax-import-meta',
        ['@babel/plugin-transform-modules-commonjs', {
            allowTopLevelThis: true,
            strictMode: false // Disable strict mode to avoid issues
        }],
        ['@babel/plugin-proposal-class-properties', { loose: true }],
        ['@babel/plugin-transform-runtime', { regenerator: true }]
    ]
};
