const catchError = require("../utils/catchError");
const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sendEmail = require("../utils/sendEmail");
const EmailCode = require("../models/EmailCode");

const getAll = catchError(async (req, res) => {
  const results = await User.findAll();
  return res.json(results);
});

const create = catchError(async (req, res) => {
  const { email, password, firstName, lastName, country, image, frontBaseUrl } =
    req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const result = await User.create({
    email,
    password: hashedPassword,
    firstName,
    lastName,
    country,
    image,
  });
  const code = require("crypto").randomBytes(32).toString("hex");
  const link = `${frontBaseUrl}/verify_email/${code}`;
  await sendEmail({
    to: email,
    subject: "verificate email for user app",
    html: `
        <h1>Hello ${firstName} ${lastName}</h1>
        <p>Thanks for signing up in user app</p>
            <a href="${link}" target="_BLANK">${link}</a>
            <h3>Thank you</h3>
    `,
  });
  EmailCode.create({ code, userId: result.id });
  return res.status(201).json({ result, message: "email sent succesfully" });
});

const getOne = catchError(async (req, res) => {
  const { id } = req.params;
  const result = await User.findByPk(id);
  if (!result) return res.sendStatus(404);
  return res.json(result);
});

const remove = catchError(async (req, res) => {
  const { id } = req.params;
  await User.destroy({ where: { id } });
  return res.sendStatus(204);
});

const update = catchError(async (req, res) => {
  const { id } = req.params;
  const { firstName, lastName, country, image } = req.body;
  const result = await User.update(
    { firstName, lastName, country, image },
    {
      where: { id },
      returning: true,
    }
  );
  return res.json(result);
});
const verifyCode = catchError(async (req, res) => {
  const { code } = req.params;
  const codeFound = await EmailCode.findOne({ where: { code } });
  if (!codeFound) return res.status(404).json({ message: "Invalid Code" });
  const user = await User.update(
    { isVerified: true },
    { where: { id: codeFound.userId }, returning: true }
  );

  await codeFound.destroy();
  return res.json(user);
});
const resetPassword = catchError(async (req, res) => {
    const { email, frontBaseUrl } = req.body;
    const { code, newPassword } = req.params;
  
    if (email) {
      // Reset password request
      const user = await User.findOne({ where: { email } });
      if (!user) {
        return res.status(401).json({ message: "User not found" });
      }
  
      const code = require("crypto").randomBytes(32).toString("hex");
      const link = `${frontBaseUrl}/reset_password/${code}`;
  
      await sendEmail({
        to: email,
        subject: "Reset Password",
        html: `
          <h1>Reset Your Password</h1>
          <p>Please click the link below to reset your password:</p>
          <a href="${link}" target="_BLANK">${link}</a>
          <h3>Thank you</h3>
        `,
      });
  
      await EmailCode.create({ code, userId: user.id });
  
      return res.json({ message: "Reset password email sent successfully" });
    } else if (code && newPassword) {
      // Reset password
      const emailCode = await EmailCode.findOne({ where: { code } });
      if (!emailCode) {
        return res.status(401).json({ message: "Invalid code" });
      }
  
      const hashedPassword = await bcrypt.hash(newPassword, 10);
  
      await User.update({ password: hashedPassword }, { where: { id: emailCode.userId } });
  
      await emailCode.destroy();
  
      return res.json({ message: "Password reset successfully" });
    } else {
      return res.status(400).json({ message: "Invalid request" });
    }
  });
  

const login = catchError(async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email } });
  if (!user) return res.status(401).json({ message: "Invalid Credentials" });
  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) return res.status(401).json({ message: "Invalid Credentials" });
  if (!user.isVerified)
    return res.status(401).json({ message: "Invalid credentials" });
  const token = jwt.sign({ user }, process.env.TOKEN_SECRET, {
    expiresIn: "1d",
  });
  return res.json({ user, token });
});

const getLoggedUser = catchError(async (req, res) => {
  const user = req.user;
  return res.json(user);
});

module.exports = {
  getAll,
  create,
  getOne,
  remove,
  update,
  verifyCode,
  login,
  getLoggedUser,
  resetPassword
};
