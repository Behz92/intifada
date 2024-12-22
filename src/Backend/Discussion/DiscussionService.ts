import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import mongoose, { Model } from 'mongoose';
import { Thread } from 'src/schemas/threads.schema';
import { Reply } from 'src/schemas/reply.schema';
import { Announcement } from 'src/schemas/announcement.schema';
import { threadId } from 'worker_threads';

@Injectable()
export class DiscussionService {
  constructor(
    @InjectModel(Thread.name, "eLearningDB") private readonly threadModel: mongoose.Model<Thread>,
    @InjectModel(Reply.name, "eLearningDB") private readonly replyModel: mongoose.Model<Reply>,
    @InjectModel(Announcement.name, "eLearningDB") private readonly announcementModel: mongoose.Model<Announcement>,
  ) {}

  // Create a new thread
  async createThread(courseId: string, title: string, content: string, createdBy: string) {
    const newThread = new this.threadModel({ courseId, title, content, createdBy });
    return newThread.save();
  }

  // Get all threads for a course
  async getThreadsByCourse(courseId: string) {
    return this.threadModel.find({ courseId }).sort({ createdAt: -1 }).exec();
  }

  // Get all replies for a thread
  async getRepliesForThread(threadId: string) {
    return this.replyModel.find({ threadId }).sort({ createdAt: 1 }).exec();
  }

  // Search threads by title or content
  async searchThreads(query: string) {
    return this.threadModel.find({ $text: { $search: query } }).exec();
  }
  // Save Announcement
  async saveAnnouncement(courseId: string, title: string, content: string, createdBy: string) {
    const announcement = new this.announcementModel({
      courseId,
      title,
      content,
      createdBy,
      createdAt: new Date(),
    });
    return announcement.save();
  }
  async getAnnouncementsByCourse(courseId: string) {
    return this.threadModel.find({ courseId }).sort({ createdAt: -1 }).exec();
  }

  async saveReply(courseId: string, threadId: string, content: string, createdBy: string) {
    const reply = new this.replyModel({
      courseId,
      threadId,
      content,
      createdBy,
      createdAt: new Date(),
    });
    return reply.save();
  }
  async saveThread(courseId: string, title: string, content: string, createdBy: string) {
    const thread = new this.threadModel({
      courseId,
      title,
      content,
      createdBy,
      createdAt: new Date(),
    });
    return thread.save();
  }
  async getThreadbyId(threadId: string){
    const thread = await this.threadModel.findOne({ _id: threadId }).exec();
    return thread;
  }
  async getReplybyId(replyId: string){
    const reply = await this.replyModel.findOne({ _id: replyId }).exec();
    return reply;
  }
  // Update a forum
  async updateThread(threadId: string, title: string, content: string) {
    const updatedThread = await this.threadModel.findByIdAndUpdate(
      threadId,
      { title, content, updatedAt: new Date() },
      { new: true },
    );
    return updatedThread;
  }

  async deleteThread(threadId: string) {
    return this.threadModel.findByIdAndDelete(threadId).exec();
  }
  async deleteReply(replyId: string) {
    return this.replyModel.findByIdAndDelete(replyId).exec();
  }
 
  
    
 
}
