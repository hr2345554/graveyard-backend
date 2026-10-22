
import 'dotenv/config';
import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_APP_PASSWORD,
  },
});

async function main() {
  try {
    await transporter.verify();
    console.log('SMTP connection successful!');

    const result = await transporter.sendMail({
      from: `"Subscription Graveyard" <${process.env.EMAIL_USER}>`,
      to: process.env.EMAIL_USER,
      subject: 'Subscription Graveyard — Email Test',
      text: 'Success! Your backend can send emails using Nodemailer.',
      html: `
        <div style="font-family:Arial,sans-serif;padding:24px">
          <h2 style="color:#8b5cf6">Subscription Graveyard</h2>
          <p>Your Nodemailer email setup is working.</p>
          <p>You're ready for the next integration step.</p>
        </div>
      `,
    });

    console.log('Test email sent:', result.messageId);
  } catch (error) {
    console.error('Email test failed:', error.message);
  }
}

main();
