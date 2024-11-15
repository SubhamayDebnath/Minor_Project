import { Router } from "express";
import { dashboard ,usersPage,skillsPage,missingPersonPage} from "../../controllers/admin/admin.page.controller.js";
import { addSkill } from "../../controllers/admin/admin.controller.js";
import {isAuthorized} from "../../middlewares/auth.middleware.js"
const router = Router();

// pages
router.get("/",isAuthorized,dashboard)
router.get("/users",isAuthorized,usersPage);
router.get("/skills",isAuthorized,skillsPage);
router.get("/missing-person",isAuthorized,missingPersonPage);

// logic

router.post('/api/v1/skill/add',isAuthorized,addSkill)

export default router;