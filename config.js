// Settings that are fine in development but unsafe or broken in
// production. Checked at startup (logged) and shown in System Health.
// Only says which setting is wrong — never prints a value.

export const isProduction = () => process.env.NODE_ENV === 'production' || Boolean(process.env.RAILWAY_ENVIRONMENT);

export function configWarnings(env = process.env) {
  const production = env.NODE_ENV === 'production' || Boolean(env.RAILWAY_ENVIRONMENT);
  if (!production) return [];
  const warnings = [];
  const smtp = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASSWORD', 'SMTP_FROM'];
  if (!env.MFA_ENCRYPTION_KEY) warnings.push({ setting: 'MFA_ENCRYPTION_KEY', severity: 'critical', message: 'Two-step verification secrets are not encrypted. Set a 64-character hex key (and never change it afterwards).' });
  if (env.REQUIRE_ADMIN_MFA === 'false') warnings.push({ setting: 'REQUIRE_ADMIN_MFA', severity: 'critical', message: 'Two-step verification is switched off for administrators. Remove this setting in production.' });
  if (env.SEED_DEMO_DATA === 'true') warnings.push({ setting: 'SEED_DEMO_DATA', severity: 'high', message: 'Demo accounts with the password "password" are enabled. Turn this off unless this server is a demo.' });
  if (!env.PUBLIC_APP_URL || /localhost|127\.0\.0\.1/.test(env.PUBLIC_APP_URL)) warnings.push({ setting: 'PUBLIC_APP_URL', severity: 'high', message: 'Links in emails won\'t point at the live website. Set it to https://www.sdpmplus.com.' });
  if (env.PUBLIC_APP_URL && !env.PUBLIC_APP_URL.startsWith('https://')) warnings.push({ setting: 'PUBLIC_APP_URL', severity: 'medium', message: 'Links in emails should use https://.' });
  if (smtp.some(name => !env[name])) warnings.push({ setting: 'SMTP_*', severity: 'high', message: 'Email sending is not fully set up, so invites, password resets and alerts are not emailed.' });
  if (env.PGSSL === 'false') warnings.push({ setting: 'PGSSL', severity: 'high', message: 'The database connection is not encrypted.' });
  if (!env.TRUST_PROXY && !env.RAILWAY_ENVIRONMENT) warnings.push({ setting: 'TRUST_PROXY', severity: 'medium', message: 'HTTPS is not enforced unless the server knows it is behind a TLS proxy.' });
  return warnings;
}
