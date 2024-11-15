import { Router } from "express";
import { dashboard ,usersPage,skillsPage} from "../../controllers/admin/admin.page.controller.js";
import {isAuthorized} from "../../middlewares/auth.middleware.js"
const router = Router();

router.get("/",isAuthorized,dashboard)
router.get("/users",isAuthorized,usersPage);
router.get("/skills",isAuthorized,skillsPage)

export default router;