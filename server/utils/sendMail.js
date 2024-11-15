import nodemailer from "nodemailer";

const sendEmail = async function (email, subject, message) {
  let transporter = nodemailer.createTransport({
    service: "gmail",
    secure: true,
    port:465,
    auth: {
      user: process.env.SMTP_EMAIL,
      pass: process.env.SMTP_PASSWORD,
    },
  });

  await transporter.sendMail({
    from: process.env.SMTP_EMAIL,
    to: email,
    subject: subject,
    html: message,
  });
};

export default sendEmail;