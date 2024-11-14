import { Router } from "express";
import {homePage} from "../../controllers/main/main.controller.js"
const router = Router();

router.get("/",homePage);

export default router