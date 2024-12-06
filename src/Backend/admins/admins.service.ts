import { Injectable,NotFoundException,BadRequestException, } from '@nestjs/common';
import { CreateAdminDto } from './dto/create-admin.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { admin } from 'src/schemas/admin.schema';
import * as bcrypt from 'bcryptjs';
import * as jwt from 'jsonwebtoken';
import { User } from 'src/schemas/user.schema';
import { Instructor } from 'src/schemas/instructor.schema';
import { decrypt } from 'dotenv';
import { Course } from 'src/schemas/course.schema';
import { Logs } from 'src/schemas/logs.schema';
import { AuthService } from '../auth/auth.service';

@Injectable()
export class AdminsService {

  // Inject UserModel and AuthenticationLogService into the constructor
  constructor(
    @InjectModel(Course.name,'eLearningDB')
    private readonly courseModel : Model<Course>, // Inject the admin model for DB operations
    @InjectModel(admin.name,'eLearningDB')
    private readonly adminModel : Model<admin>, // Inject the admin model for DB operations
    @InjectModel(Instructor.name, 'eLearningDB')
    private readonly InstructorModel: Model<Instructor>, // Inject the Instructor model for DB operations
    @InjectModel(User.name, 'eLearningDB')
    private readonly UserModel: Model<User>, // Inject the User model for DB operations
    @InjectModel(Logs.name,'eLearningDB')
    private readonly logsModel:Model<Logs>,
    private readonly authService: AuthService, // Inject AuthService

  ) {}

  // Register a new Admin
  async registerAdmin(createAdminDto: CreateAdminDto) {
    return await this.authService.registerUser(createAdminDto, 'admin');
  }

  // Login Admin
  async loginAdmin(email: string, password: string) {
    return await this.authService.login(email, password, 'admin');
  } 
}






