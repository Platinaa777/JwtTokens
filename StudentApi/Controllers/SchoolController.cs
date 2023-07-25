using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using StudentApi.Data;
using StudentApi.DTOs;
using StudentApi.Models;

namespace StudentApi.Controllers;

/// <summary>
/// Simple Web Api Controller for studying purposes
/// In AuthController contains JWT tokens implementations
/// </summary>
[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
[ApiController]
[Route("api/[controller]")]
public class SchoolController : ControllerBase
{
    private readonly DataContext _context;

    public SchoolController(DataContext context)
    {
        _context = context;
    }

    [HttpGet]
    public async Task<ActionResult<Student>> GetStudentById(int id)
    {
        var student = await _context.Students
            .Include(c => c.Lessons)
            .FirstOrDefaultAsync(c => c.Id == id);

        if (student == null)
            return NotFound("Student does not exist");

        return Ok(student);
    }

    [HttpPost]
    public async Task<ActionResult<List<Student>>> AddStudent([FromBody] StudentCreateDto student)
    {
        var newStudent = new Student()
        {
            Name = student.Name,
            Surname = student.Surname,
        };

        var newLessons = student.Lessons
            .Select(x => new Lesson()
            {
                Name = x.Name,
                MaxGrade = x.MaxGrade,
                Students = new List<Student>{newStudent},
            }).ToList();

        newStudent.Lessons = newLessons;

        await _context.Students.AddAsync(newStudent);
        await _context.SaveChangesAsync();

        return Ok(await _context.Students.Include(c => c.Lessons).ToListAsync());
    }
}