const {
  getAll,
  create,
  getOne,
  remove,
  update,
  login,
  getLoggedUser,
  verifyCode,
  resetPassword,
} = require("../controllers/user.controllers");
const express = require("express");
const verifyJWT = require("../utils/verifyJWT");

const userRouter = express.Router();

userRouter.route("/").get(getAll, verifyJWT).post(create);

userRouter.route("/reset_password").post(resetPassword, verifyJWT)

userRouter.route("/login").post(login);

userRouter.route("/me").get(verifyJWT, getLoggedUser);

userRouter.route("/verify/:code").get(verifyCode);

userRouter
  .route("/:id")
  .get(verifyJWT, getOne)
  .delete(verifyJWT, remove)
  .put(verifyJWT, update);

module.exports = userRouter;
