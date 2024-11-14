import { Router } from "express";
import {registerPage} from "../../controllers/auth/auth.page.controller.js"
const router = Router();

router.get("/register",registerPage);

export default router