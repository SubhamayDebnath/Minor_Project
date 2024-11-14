import { Router } from "express";
import {registerPage,loginPage} from "../../controllers/auth/auth.page.controller.js"
import { register } from "../../controllers/auth/auth.controller.js";
const router = Router();
// pages
router.get("/register",registerPage);
router.get("/login",loginPage)
// methods
router.post("/api/v1/register",register)
export default router