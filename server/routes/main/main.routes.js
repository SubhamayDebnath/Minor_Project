import { Router } from "express";
import {homePage,errorPage,profilePage} from "../../controllers/main/main.controller.js"
import {isAuthenticated} from '../../middlewares/auth.middleware.js'
const router = Router();

router.get("/",isAuthenticated,homePage);
router.get("/profile",isAuthenticated,profilePage);
router.get('/error',isAuthenticated,errorPage);

export default router