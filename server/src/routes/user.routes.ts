import { Router } from "express";
import {
  signinUser,
  test,
  renewAccessToken,
  initiateLogin,
  verifyLoginOtp,
  logoutUser,
} from "../controllers/user";
import { verifyAccessToken } from "../middleware/authenticated";

const router = Router();
router.post("/siginUser", signinUser);
router.post("/initateLogin", initiateLogin);
router.post("/verifyLoginOtp", verifyLoginOtp);
router.post("/logout", verifyAccessToken, logoutUser);

router.post("/refresh", renewAccessToken);
router.get("/test", test);
export default router;
