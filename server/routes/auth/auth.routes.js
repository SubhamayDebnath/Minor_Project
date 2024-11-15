import { Router } from "express";
import {registerPage,loginPage} from "../../controllers/auth/auth.page.controller.js"
import { register,login,logout } from "../../controllers/auth/auth.controller.js";
import {isLoggedIn} from '../../middlewares/auth.middleware.js'
const router = Router();
// pages
router.get("/register",isLoggedIn,registerPage);
router.get("/login",isLoggedIn,loginPage);
router.get("/logout",logout)
// methods
router.post("/api/v1/register",isLoggedIn,register);
router.post("/api/v1/login",isLoggedIn,login)
export default router