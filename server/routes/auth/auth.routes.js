import { Router } from "express";
import {registerPage,loginPage} from "../../controllers/auth/auth.page.controller.js"
const router = Router();

router.get("/register",registerPage);
router.get("/login",loginPage)

export default router