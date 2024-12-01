// authentication-log.controller.ts or logs.controller.ts

import { Controller, Get, Post, Body, Param, UseGuards } from '@nestjs/common';
import { AuthenticationLogService } from './authentication-log.service';



@Controller('logs')
export class AuthenticationLogController {
  constructor(private readonly authLogService: AuthenticationLogService) { }
}
