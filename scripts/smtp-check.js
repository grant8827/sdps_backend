import { sendEmail, verifyEmailConnection } from '../mailer.js';

const recipient = process.argv[2];
if (!recipient?.includes('@')) {
  console.error('Usage: npm run email:test -- recipient@example.com');
  process.exitCode = 1;
} else {
  await verifyEmailConnection();
  const result = await sendEmail({
    to: recipient,
    subject: 'SDPMPlus email test',
    text: 'Mailtrap SMTP is configured correctly.',
    html: '<p>Mailtrap SMTP is configured correctly.</p>',
  });
  console.log(`Test email sent (${result.messageId}).`);
}
