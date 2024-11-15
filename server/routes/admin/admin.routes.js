import { Router } from "express";
import { dashboard ,usersPage,skillsPage,missingPersonPage,skillUpdateForm} from "../../controllers/admin/admin.page.controller.js";
import { addSkill,updateSkill ,deleteSkill} from "../../controllers/admin/admin.controller.js";
import {isAuthorized} from "../../middlewares/auth.middleware.js"
const router = Router();

// pages
router.get("/",isAuthorized,dashboard)
router.get("/users",isAuthorized,usersPage);
router.get("/skills",isAuthorized,skillsPage);
router.get("/missing-person",isAuthorized,missingPersonPage);
router.get("/skill/update/:id",isAuthorized,skillUpdateForm);

// logic

router.post('/api/v1/skill/add',isAuthorized,addSkill)
router.put('/api/v1/skill/update',isAuthorized,updateSkill)
router.delete('/api/v1/skill/delete/:id',isAuthorized,deleteSkill);

export default router;