import uvicorn


def dev():
    uvicorn.run(
        "jack_the_gripper.api.main:app", host="localhost", port=8000, reload=True
    )
