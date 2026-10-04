var builder = DistributedApplication.CreateBuilder(args);

// Workload containers and PostgreSQL are composed here during milestone M1.
// Application projects are deliberately not added with AddProject: the PRD
// requires all three applications to run as containers while AppHost stays on
// the development host.

builder.Build().Run();
