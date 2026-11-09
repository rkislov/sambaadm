module.exports = {
  content: ['./internal/web/templates/**/*.html', './internal/web/static/js/**/*.js'],
  corePlugins: { preflight: false },
  theme: { extend: { colors: { brand: { 50: '#effaf8', 100: '#d9f1eb', 600: '#0f766e', 700: '#115e59' } }, boxShadow: { float: '0 14px 48px -16px rgb(15 23 42 / 0.22)' } } },
};
