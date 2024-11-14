import { Router } from "express";
import {homePage,errorPage} from "../../controllers/main/main.controller.js"
import {isAuthenticated} from '../../middlewares/auth.middleware.js'
const router = Router();

router.get("/",isAuthenticated,homePage);
router.get('/error',isAuthenticated,errorPage)

export default router