import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './Backend/users/users.module';
import { CoursesModule } from './Backend/courses/courses.module';
import { ModulesModule } from './Backend/modules/modules.module';
import { QuizzesModule } from './Backend/quizzes/quizzes.module';
import { MongooseModule } from '@nestjs/mongoose';
import { NoteModule } from './Backend/note/note.module';
import { RecommendationModule } from './Backend/recommendation/recommendation.module';
import { ConfigurationModule } from './Backend/configuration/configuration.module';
import { NotificationModule } from './Backend/notification/notification.module';
import { FeedbackModule } from './Backend/feedback/feedback.module';
import { JwtModule } from '@nestjs/jwt';
import { CertificateModule } from './Backend/certificate/certificate.module';
import { BackupModule } from './Backend/backup/backup.module';
import { InstructorModule } from 'src/Backend/instructor/instructor.module';
import { AdminsModule } from './Backend/admins/admins.module';
import { LogsModule } from './Backend/logs/logs.module';
import { ProgressModule } from './Backend/progress/progress.module';
import { AuthModule } from './Backend/auth/auth.module';
import { ServeStaticModule } from '@nestjs/serve-static';
import path, { join } from 'path';
import { ChatModule } from './Backend/chat/chat.module';
import { ForumModule } from './Backend/forums/forum.module';
import { ChatHistoryModule } from './Backend/chat-history/chat-history.module';
import { InstructorController } from './instructor/instructor.controller';
// import { DiscussionModule } from './Backend/Discussion/DiscussionModule';
import { DiscussionModule } from './Backend/DiscussionForum/discussion.module';
import { ThreadModule } from './Backend/threads/thread.module';
import { ReplyModule } from './Backend/replies/reply.module';
@Module({
  imports: [
    MongooseModule.forRoot(
      'mongodb://E_Learning:E_Learning_1@ac-godgsxx-shard-00-00.tsojh1d.mongodb.net:27017,ac-godgsxx-shard-00-01.tsojh1d.mongodb.net:27017,ac-godgsxx-shard-00-02.tsojh1d.mongodb.net:27017/?replicaSet=atlas-mslkhi-shard-0&ssl=true&authSource=admin',
      {
        connectionName: 'eLearningDB', // For eLearning database
      },
    ),
    MongooseModule.forRoot(
      'mongodb://E_Learning:E_Learning_1@ac-godgsxx-shard-00-00.tsojh1d.mongodb.net:27017,ac-godgsxx-shard-00-01.tsojh1d.mongodb.net:27017,ac-godgsxx-shard-00-02.tsojh1d.mongodb.net:27017/?replicaSet=atlas-mslkhi-shard-0&ssl=true&authSource=admin',
      {
        connectionName: 'dataManagementDB', // For data management database
      },
    ),
    ServeStaticModule.forRoot({
      rootPath: join('C:', 'Users', 'Omar Hossam', 'Downloads'), // Folder where PDFs are stored
      serveRoot: '/files', // URL path prefix for accessing the PDFs
    }),
    UsersModule,
    CoursesModule,
    ModulesModule,
    QuizzesModule,
    NoteModule,
    RecommendationModule,
    ConfigurationModule,
    NotificationModule,
    FeedbackModule,
    CertificateModule,
    BackupModule,
    LogsModule,

    JwtModule.register({
      secret: process.env.JWT_SECRET || 'default_secret', // Use environment variable for secret
      signOptions: { expiresIn: '24h' }, // Token expiration time
      global: true,
    }),
    InstructorModule,
    AdminsModule,
    ProgressModule,
    AuthModule,
    ChatModule,

    ChatHistoryModule,
    DiscussionModule,
    ForumModule,
    ThreadModule,
    ReplyModule,
    DiscussionModule,
  ],
  controllers: [AppController, InstructorController],
  providers: [AppService],
})
export class AppModule {}
