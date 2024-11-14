import { Router } from "express";
import {homePage,errorPage} from "../../controllers/main/main.controller.js"
const router = Router();

router.get("/",homePage);
router.get('/error',errorPage)

export default router